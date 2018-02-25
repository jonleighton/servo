/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use app_units::Au;
use font_context::FontSource;
use font_template::{FontTemplate, FontTemplateDescriptor};
use fontsan;
use ipc_channel::ipc::{self, IpcReceiver, IpcSender};
use net_traits::{CoreResourceThread, FetchResponseMsg, fetch_async};
use net_traits::request::{Destination, RequestInit};
use platform::font_context::FontContextHandle;
use platform::font_list::SANS_SERIF_FONT_FAMILY;
use platform::font_list::for_each_available_family;
use platform::font_list::for_each_variation;
use platform::font_list::last_resort_font_families;
use platform::font_list::system_default_family;
use platform::font_template::FontTemplateData;
use servo_atoms::Atom;
use servo_url::ServoUrl;
use std::borrow::ToOwned;
use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::thread;
use std::u32;
use style::font_face::{EffectiveSources, Source};
use style::values::computed::font::{SingleFontFamily, FamilyName};
use webrender_api;

/// A list of font templates that make up a given font family.
pub struct FontTemplates {
    templates: Vec<FontTemplate>,
}

impl FontTemplates {
    pub fn new() -> FontTemplates {
        FontTemplates {
            templates: vec!(),
        }
    }

    /// Find a font in this family that matches a given descriptor.
    pub fn find_font_for_style(&mut self, desc: &FontTemplateDescriptor, fctx: &FontContextHandle)
                               -> Option<Arc<FontTemplateData>> {
        // TODO(Issue #189): optimize lookup for
        // regular/bold/italic/bolditalic with fixed offsets and a
        // static decision table for fallback between these values.
        for template in &mut self.templates {
            let maybe_template = template.data_for_descriptor(fctx, desc);
            if maybe_template.is_some() {
                return maybe_template;
            }
        }

        // We didn't find an exact match. Do more expensive fuzzy matching.
        // TODO(#190): Do a better job.
        let (mut best_template_data, mut best_distance) = (None, u32::MAX);
        for template in &mut self.templates {
            if let Some((template_data, distance)) =
                    template.data_for_approximate_descriptor(fctx, desc) {
                if distance < best_distance {
                    best_template_data = Some(template_data);
                    best_distance = distance
                }
            }
        }
        if best_template_data.is_some() {
            return best_template_data
        }

        // If a request is made for a font family that exists,
        // pick the first valid font in the family if we failed
        // to find an exact match for the descriptor.
        for template in &mut self.templates {
            let maybe_template = template.get();
            if maybe_template.is_some() {
                return maybe_template;
            }
        }

        None
    }

    pub fn add_template(&mut self, identifier: Atom, maybe_data: Option<Vec<u8>>) {
        for template in &self.templates {
            if *template.identifier() == identifier {
                return;
            }
        }

        if let Ok(template) = FontTemplate::new(identifier, maybe_data) {
            self.templates.push(template);
        }
    }
}

/// Commands that the FontContext sends to the font cache thread.
#[derive(Debug, Deserialize, Serialize)]
pub enum Command {
    GetFontTemplate(SingleFontFamily, FontTemplateDescriptor, IpcSender<Reply>),
    GetLastResortFontTemplate(FontTemplateDescriptor, IpcSender<Reply>),
    GetWebrenderKey(Arc<FontTemplateData>, Au, IpcSender<webrender_api::FontInstanceKey>),
    AddWebFont(LowercaseString, EffectiveSources, IpcSender<()>),
    AddDownloadedWebFont(LowercaseString, ServoUrl, Vec<u8>, IpcSender<()>),
    Exit(IpcSender<()>),
    Ping,
}

/// Reply messages sent from the font cache thread to the FontContext caller.
#[derive(Debug, Deserialize, Serialize)]
pub enum Reply {
    GetFontTemplateReply(Option<Arc<FontTemplateData>>),
}

/// The font cache thread itself. It maintains a list of reference counted
/// font templates that are currently in use.
struct FontCache {
    port: IpcReceiver<Command>,
    channel_to_self: IpcSender<Command>,
    generic_fonts: HashMap<SingleFontFamily, LowercaseString>,
    local_families: HashMap<LowercaseString, FontTemplates>,
    web_families: HashMap<LowercaseString, FontTemplates>,
    font_context: FontContextHandle,
    core_resource_thread: CoreResourceThread,
    webrender_api: webrender_api::RenderApi,
    webrender_fonts: HashMap<Atom, webrender_api::FontKey>,
    font_instances: HashMap<(webrender_api::FontKey, Au), webrender_api::FontInstanceKey>,
}

fn populate_generic_fonts() -> HashMap<SingleFontFamily, LowercaseString> {
    let mut generic_fonts = HashMap::with_capacity(5);

    append_map(&mut generic_fonts, SingleFontFamily::Generic(atom!("serif")), "Times New Roman");
    append_map(&mut generic_fonts, SingleFontFamily::Generic(atom!("sans-serif")), SANS_SERIF_FONT_FAMILY);
    append_map(&mut generic_fonts, SingleFontFamily::Generic(atom!("cursive")), "Apple Chancery");
    append_map(&mut generic_fonts, SingleFontFamily::Generic(atom!("fantasy")), "Papyrus");
    append_map(&mut generic_fonts, SingleFontFamily::Generic(atom!("monospace")), "Menlo");

    fn append_map(generic_fonts: &mut HashMap<SingleFontFamily, LowercaseString>,
                  font_family: SingleFontFamily,
                  mapped_name: &str) {
        let family_name = {
            let opt_system_default = system_default_family(font_family.name());
            match opt_system_default {
                Some(system_default) => LowercaseString::new(&system_default),
                None => LowercaseString::new(mapped_name)
            }
        };

        generic_fonts.insert(font_family, family_name);
    }


    generic_fonts
}

impl FontCache {
    fn run(&mut self) {
        loop {
            let msg = self.port.recv().unwrap();

            match msg {
                Command::GetFontTemplate(family, descriptor, result) => {
                    let maybe_font_template = self.find_font_template(&family, &descriptor);
                    let _ = result.send(Reply::GetFontTemplateReply(maybe_font_template));
                }
                Command::GetLastResortFontTemplate(descriptor, result) => {
                    let font_template = self.last_resort_font_template(&descriptor);
                    let _ = result.send(Reply::GetFontTemplateReply(Some(font_template)));
                }
                Command::GetWebrenderKey(template, size, result) => {
                    let _ = result.send(self.webrender_key(template, size));
                }
                Command::AddWebFont(family_name, sources, result) => {
                    self.handle_add_web_font(family_name, sources, result);
                }
                Command::AddDownloadedWebFont(family_name, url, bytes, result) => {
                    let templates = &mut self.web_families.get_mut(&family_name).unwrap();
                    templates.add_template(Atom::from(url.to_string()), Some(bytes));
                    drop(result.send(()));
                }
                Command::Ping => (),
                Command::Exit(result) => {
                    let _ = result.send(());
                    break;
                }
            }
        }
    }

    fn handle_add_web_font(&mut self,
                           family_name: LowercaseString,
                           mut sources: EffectiveSources,
                           sender: IpcSender<()>) {
        let src = if let Some(src) = sources.next() {
            src
        } else {
            sender.send(()).unwrap();
            return;
        };

        if !self.web_families.contains_key(&family_name) {
            let templates = FontTemplates::new();
            self.web_families.insert(family_name.clone(), templates);
        }

        match src {
            Source::Url(url_source) => {
                // https://drafts.csswg.org/css-fonts/#font-fetching-requirements
                let url = match url_source.url.url() {
                    Some(url) => url.clone(),
                    None => return,
                };

                let request = RequestInit {
                    url: url.clone(),
                    destination: Destination::Font,
                    // TODO: Add a proper origin - Can't import GlobalScope from gfx
                    // We can leave origin to be set by default
                    .. RequestInit::default()
                };

                let channel_to_self = self.channel_to_self.clone();
                let bytes = Mutex::new(Vec::new());
                let response_valid = Mutex::new(false);
                debug!("Loading @font-face {} from {}", family_name, url);
                fetch_async(request, &self.core_resource_thread, move |response| {
                    match response {
                        FetchResponseMsg::ProcessRequestBody |
                        FetchResponseMsg::ProcessRequestEOF => (),
                        FetchResponseMsg::ProcessResponse(meta_result) => {
                            trace!("@font-face {} metadata ok={:?}", family_name, meta_result.is_ok());
                            *response_valid.lock().unwrap() = meta_result.is_ok();
                        }
                        FetchResponseMsg::ProcessResponseChunk(new_bytes) => {
                            trace!("@font-face {} chunk={:?}", family_name, new_bytes);
                            if *response_valid.lock().unwrap() {
                                bytes.lock().unwrap().extend(new_bytes.into_iter())
                            }
                        }
                        FetchResponseMsg::ProcessResponseEOF(response) => {
                            trace!("@font-face {} EOF={:?}", family_name, response);
                            if response.is_err() || !*response_valid.lock().unwrap() {
                                let msg = Command::AddWebFont(family_name.clone(), sources.clone(), sender.clone());
                                channel_to_self.send(msg).unwrap();
                                return;
                            }
                            let bytes = mem::replace(&mut *bytes.lock().unwrap(), vec![]);
                            trace!("@font-face {} data={:?}", family_name, bytes);
                            let bytes = match fontsan::process(&bytes) {
                                Ok(san) => san,
                                Err(_) => {
                                    // FIXME(servo/fontsan#1): get an error message
                                    debug!("Sanitiser rejected web font: \
                                            family={} url={:?}", family_name, url);
                                    let msg = Command::AddWebFont(family_name.clone(), sources.clone(), sender.clone());
                                    channel_to_self.send(msg).unwrap();
                                    return;
                                },
                            };
                            let command =
                                Command::AddDownloadedWebFont(family_name.clone(),
                                                              url.clone(),
                                                              bytes,
                                                              sender.clone());
                            channel_to_self.send(command).unwrap();
                        }
                    }
                });
            }
            Source::Local(ref font) => {
                let font_face_name = LowercaseString::new(&font.name);
                let templates = &mut self.web_families.get_mut(&family_name).unwrap();
                let mut found = false;
                for_each_variation(&font_face_name, |path| {
                    found = true;
                    templates.add_template(Atom::from(&*path), None);
                });
                if found {
                    sender.send(()).unwrap();
                } else {
                    let msg = Command::AddWebFont(family_name, sources, sender);
                    self.channel_to_self.send(msg).unwrap();
                }
            }
        }
    }

    fn refresh_local_families(&mut self) {
        self.local_families.clear();
        for_each_available_family(|family_name| {
            let family_name = LowercaseString::new(&family_name);
            if !self.local_families.contains_key(&family_name) {
                let templates = FontTemplates::new();
                self.local_families.insert(family_name, templates);
            }
        });
    }

    fn transform_family(&self, family: &SingleFontFamily) -> LowercaseString {
        match self.generic_fonts.get(family) {
            None => LowercaseString::new(family.name()),
            Some(mapped_family) => (*mapped_family).clone()
        }
    }

    fn find_font_in_local_family(&mut self, family_name: &LowercaseString, desc: &FontTemplateDescriptor)
                                -> Option<Arc<FontTemplateData>> {
        // TODO(Issue #188): look up localized font family names if canonical name not found
        // look up canonical name
        if self.local_families.contains_key(family_name) {
            debug!("FontList: Found font family with name={}", &**family_name);
            let s = self.local_families.get_mut(family_name).unwrap();

            if s.templates.is_empty() {
                for_each_variation(family_name, |path| {
                    s.add_template(Atom::from(&*path), None);
                });
            }

            // TODO(Issue #192: handle generic font families, like 'serif' and 'sans-serif'.
            // if such family exists, try to match style to a font

            s.find_font_for_style(desc, &self.font_context)
        } else {
            debug!("FontList: Couldn't find font family with name={}", &**family_name);
            None
        }
    }

    fn find_font_in_web_family(&mut self, family: &SingleFontFamily, desc: &FontTemplateDescriptor)
                                -> Option<Arc<FontTemplateData>> {
        let family_name = LowercaseString::new(family.name());

        if self.web_families.contains_key(&family_name) {
            let templates = self.web_families.get_mut(&family_name).unwrap();
            templates.find_font_for_style(desc, &self.font_context)
        } else {
            None
        }
    }

    fn find_font_template(
        &mut self,
        family: &SingleFontFamily,
        desc: &FontTemplateDescriptor,
    ) -> Option<Arc<FontTemplateData>>
    {
        self.find_font_in_web_family(family, desc)
            .or_else(|| {
                let transformed_family = self.transform_family(family);
                self.find_font_in_local_family(&transformed_family, desc)
            })
    }

    fn last_resort_font_template(&mut self, desc: &FontTemplateDescriptor) -> Arc<FontTemplateData> {
        let last_resort = last_resort_font_families();

        for family in &last_resort {
            let family = LowercaseString::new(family);
            let font = self.find_font_in_local_family(&family, desc);

            if font.is_some() {
                return font.unwrap()
            }
        }

        panic!("Unable to find any fonts that match (do you have fallback fonts installed?)");
    }

    fn webrender_key(&mut self, template: Arc<FontTemplateData>, size: Au) -> webrender_api::FontInstanceKey {
        let webrender_api = &self.webrender_api;

        let font_key = *self.webrender_fonts.entry(template.identifier.clone()).or_insert_with(|| {
            let font_key = webrender_api.generate_font_key();
            let mut updates = webrender_api::ResourceUpdates::new();
            match (template.bytes_if_in_memory(), template.native_font()) {
                (Some(bytes), _) => updates.add_raw_font(font_key, bytes, 0),
                (None, Some(native_font)) => updates.add_native_font(font_key, native_font),
                (None, None) => updates.add_raw_font(font_key, template.bytes().clone(), 0),
            }
            webrender_api.update_resources(updates);
            font_key
        });

        *self.font_instances
            .entry((font_key, size))
            .or_insert_with(|| {
                let key = webrender_api.generate_font_instance_key();
                let mut updates = webrender_api::ResourceUpdates::new();
                updates.add_font_instance(key,
                                          font_key,
                                          size,
                                          None,
                                          None,
                                          Vec::new());
                webrender_api.update_resources(updates);
                key
            })
    }
}

/// The public interface to the font cache thread, used by per-thread `FontContext` instances (via
/// the `FontSource` trait), and also by layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FontCacheThread {
    chan: IpcSender<Command>,
}

impl FontCacheThread {
    pub fn new(core_resource_thread: CoreResourceThread,
               webrender_api: webrender_api::RenderApi) -> FontCacheThread {
        let (chan, port) = ipc::channel().unwrap();

        let channel_to_self = chan.clone();
        thread::Builder::new().name("FontCacheThread".to_owned()).spawn(move || {
            // TODO: Allow users to specify these.
            let generic_fonts = populate_generic_fonts();

            let mut cache = FontCache {
                port: port,
                channel_to_self,
                generic_fonts,
                local_families: HashMap::new(),
                web_families: HashMap::new(),
                font_context: FontContextHandle::new(),
                core_resource_thread,
                webrender_api,
                webrender_fonts: HashMap::new(),
                font_instances: HashMap::new(),
            };

            cache.refresh_local_families();
            cache.run();
        }).expect("Thread spawning failed");

        FontCacheThread {
            chan: chan,
        }
    }

    pub fn add_web_font(&self, family: FamilyName, sources: EffectiveSources, sender: IpcSender<()>) {
        self.chan.send(Command::AddWebFont(LowercaseString::new(&family.name), sources, sender)).unwrap();
    }

    pub fn exit(&self) {
        let (response_chan, response_port) = ipc::channel().unwrap();
        self.chan.send(Command::Exit(response_chan)).expect("Couldn't send FontCacheThread exit message");
        response_port.recv().expect("Couldn't receive FontCacheThread reply");
    }
}

impl FontSource for FontCacheThread {
    fn webrender_key(&mut self, template: Arc<FontTemplateData>, size: Au) -> webrender_api::FontInstanceKey {
        let (response_chan, response_port) =
            ipc::channel().expect("failed to create IPC channel");
        self.chan.send(Command::GetWebrenderKey(template, size, response_chan))
            .expect("failed to send message to font cache thread");

        let instance_key = response_port.recv();
        if instance_key.is_err() {
            let font_thread_has_closed = self.chan.send(Command::Ping).is_err();
            assert!(font_thread_has_closed, "Failed to receive a response from live font cache");
            panic!("Font cache thread has already exited.");
        }
        instance_key.unwrap()
    }

    fn find_font_template(
        &mut self,
        family: SingleFontFamily,
        desc: FontTemplateDescriptor,
    ) -> Option<Arc<FontTemplateData>>
    {
        let (response_chan, response_port) =
            ipc::channel().expect("failed to create IPC channel");
        self.chan.send(Command::GetFontTemplate(family, desc, response_chan))
            .expect("failed to send message to font cache thread");

        let reply = response_port.recv();

        if reply.is_err() {
            let font_thread_has_closed = self.chan.send(Command::Ping).is_err();
            assert!(font_thread_has_closed, "Failed to receive a response from live font cache");
            panic!("Font cache thread has already exited.");
        }

        match reply.unwrap() {
            Reply::GetFontTemplateReply(data) => {
                data
            }
        }
    }

    fn last_resort_font_template(&mut self, desc: FontTemplateDescriptor) -> Arc<FontTemplateData> {
        let (response_chan, response_port) =
            ipc::channel().expect("failed to create IPC channel");
        self.chan.send(Command::GetLastResortFontTemplate(desc, response_chan))
            .expect("failed to send message to font cache thread");

        let reply = response_port.recv();
        if reply.is_err() {
            let font_thread_has_closed = self.chan.send(Command::Ping).is_err();
            assert!(font_thread_has_closed, "Failed to receive a response from live font cache");
            panic!("Font cache thread has already exited.");
        }

        match reply.unwrap() {
            Reply::GetFontTemplateReply(data) => {
                data.unwrap()
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct LowercaseString {
    inner: String,
}

impl LowercaseString {
    pub fn new(s: &str) -> LowercaseString {
        LowercaseString {
            inner: s.to_lowercase(),
        }
    }
}

impl Deref for LowercaseString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        &*self.inner
    }
}

impl fmt::Display for LowercaseString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}
