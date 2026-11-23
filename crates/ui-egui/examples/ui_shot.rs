//! Renders the whole VSlide window offscreen (wgpu, no window) to a PNG, with the sample deck.
//!
//! `cargo run -p vslide-ui-egui --example ui_shot -- out.png [--dark] [--tab NAME]`; `UI_SHOT_GTK=1`
//! wears the desktop's GTK theme, as the app does.

use vslide_engine::Session;
use vslide_ui_egui::{Services, SlideApp};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = args.iter().find(|a| a.ends_with(".png")).cloned().unwrap_or_else(|| "vslide.png".into());
    let dark = args.iter().any(|a| a == "--dark");
    let tab = args.iter().position(|a| a == "--tab").and_then(|i| args.get(i + 1)).cloned();
    let mut app = SlideApp::new(Session::new(), Services::default());
    vslide_engine::sample::open_sample(&mut app.session).expect("sample deck");
    if dark {
        app.ui.brightness = vslide_ui_egui::theme::Brightness::Dark;
    }
    if let Some(t) = tab {
        app.ui.tab = t;
    }
    if std::env::var_os("UI_SHOT_GTK").is_some() {
        let ctx = egui::Context::default();
        vslide_ui_egui::gtk_theme::enable(&ctx);
        vslide_ui_egui::theme::refresh_gtk();
    }
    let mut harness =
        egui_kittest::Harness::builder().with_size(egui::vec2(1440.0, 900.0)).with_pixels_per_point(1.5).with_max_steps(200).wgpu().build_ui_state(
            |ui, app: &mut SlideApp| {
                let ctx = ui.ctx().clone();
                app.logic(&ctx);
                app.ui(ui);
            },
            app,
        );
    for _ in 0..30 {
        harness.step();
    }
    harness.render().expect("render").save(&out).expect("save png");
    println!("{out}");
}
