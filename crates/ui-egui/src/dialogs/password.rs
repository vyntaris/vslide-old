//! Vyntaris: the password of a password-protected PowerPoint file, asked for when it opens.

use super::{Dialog, SlideApp, Ui, Value, buttons, json};

impl Dialog {
    /// Asks for the password of the presentation `command` (`file.open`, `file.openBytes`) was
    /// given `params` for, and opens it.
    pub fn password(command: &str, name: &str, params: Value) -> Self {
        Dialog { params: json!({"command": command, "name": name, "params": params}), ..Dialog::new("password") }
    }
}

impl SlideApp {
    /// `path`'s file is password-protected: ask for the password, then open it with `command`.
    pub(crate) fn ask_password(&mut self, command: &str, path: &str, params: Value) {
        let name = std::path::Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.to_string());
        self.dialog = Some(Dialog::password(command, &name, params));
    }
}

/// Returns true when the dialog should close.
pub(super) fn password_dialog(app: &mut SlideApp, ui: &mut Ui, d: &mut Dialog) -> bool {
    let name = d.params.get("name").and_then(Value::as_str).unwrap_or("The presentation").to_string();
    ui.label(format!("{name} is protected with a password."));
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Password:");
        let r = ui.add(egui::TextEdit::singleline(d.secret.as_mut_string()).password(true).desired_width(220.0));
        if d.secret.is_empty() && !r.has_focus() {
            r.request_focus();
        }
    });
    if let Some(m) = d.fields.get("message").filter(|m| !m.is_empty()) {
        ui.label(egui::RichText::new(m.as_str()).small().color(ui.visuals().error_fg_color));
    }
    let (ok, cancel) = buttons(ui, "OK");
    if ok && !d.secret.is_empty() {
        let command = d.params.get("command").and_then(Value::as_str).unwrap_or("file.open").to_string();
        let mut p = d.params.get("params").cloned().unwrap_or_else(|| json!({}));
        if let Some(o) = p.as_object_mut() {
            o.insert("password".into(), json!(d.secret.as_str()));
        }
        match app.session.execute(&command, &p) {
            Ok(_) => {
                if let Some(path) = d.params.get("params").and_then(|p| p.get("path")).and_then(Value::as_str) {
                    app.note_recent(path);
                }
                return true;
            }
            Err(e) if vslide_engine::cmd::file::wrong_password(&e.to_string()) => {
                d.fields.insert("message".into(), "That password isn't right. Check it (passwords are case-sensitive) and try again.".into());
                d.secret.as_mut_string().clear();
            }
            Err(e) => {
                app.notify(e.to_string());
                return true;
            }
        }
    }
    cancel
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use crate::{Services, SlideApp};
    use vslide_engine::Session;

    #[test]
    fn a_password_protected_presentation_asks_for_its_password() {
        use egui_kittest::kittest::Queryable as _;
        let mut harness = egui_kittest::Harness::builder().with_size(egui::vec2(1200.0, 800.0)).build_ui_state(
            |ui, app: &mut SlideApp| {
                app.logic(ui.ctx());
                app.ui(ui);
            },
            SlideApp::new(Session::with_new(), Services::default()),
        );
        harness.run_steps(2);
        let plain = vslide_engine::cmd::file::save_bytes(&harness.state().session.active().unwrap().doc, "pptx").unwrap();
        let enc = vyntaris_office_crypt::encrypt_with_spin_count(&plain, "geheim", 8).unwrap();
        harness.state_mut().open_or_insert_bytes("secret.pptx", &enc);
        assert_eq!(harness.state().dialog.as_ref().map(|d| d.id.as_str()), Some("password"));
        harness.run_steps(3);
        // a wrong one asks again
        for (typed, open) in [("nope", true), ("geheim", false)] {
            harness.input_mut().events.push(egui::Event::Text(typed.into()));
            harness.run_steps(2);
            harness.get_by_label("OK").click();
            harness.run_steps(3);
            assert_eq!(harness.state().dialog.is_some(), open, "{typed}");
        }
        let app = harness.state();
        assert_eq!(app.session.documents().len(), 2);
        let d = app.session.active().unwrap();
        assert!(d.password.is_some());
        // saved as PowerPoint, encrypted again; as VSlide's own format, as it is
        assert!(vyntaris_office_crypt::is_encrypted(&vslide_engine::cmd::file::doc_bytes(d, "pptx").unwrap()));
        assert!(!vyntaris_office_crypt::is_encrypted(&vslide_engine::cmd::file::doc_bytes(d, "vslide").unwrap()));
    }
}
