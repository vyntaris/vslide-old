//! The desktop's GTK theme, worn by the interface: the colours a GTK theme names with
//! `@define-color` (libadwaita's names: `window_bg_color`, `accent_bg_color`, …) in
//! `$XDG_CONFIG_HOME/gtk-4.0/gtk.css`, else gtk-3.0's. The Vyntaris shell writes them there from its
//! flavour and accent, and rewrites the file when either changes; a background thread notices (it
//! looks at the file's time, not its contents, every 1.5 s) and the interface is restyled.
//!
//! Off until the app turns it on ([`enable`]), so tests see the built-in palettes.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use egui::Color32;

/// The colours a GTK theme defines, by name.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GtkColors {
    colors: HashMap<String, Color32>,
}

impl GtkColors {
    pub fn get(&self, name: &str) -> Option<Color32> {
        self.colors.get(name).copied()
    }

    /// Whether the theme is dark: its window background is.
    pub fn dark(&self) -> Option<bool> {
        let c = self.get("window_bg_color")?;
        let l = 0.2126 * f32::from(c.r()) + 0.7152 * f32::from(c.g()) + 0.0722 * f32::from(c.b());
        Some(l < 128.0)
    }

    pub fn is_empty(&self) -> bool {
        self.colors.is_empty()
    }
}

/// `@define-color name value;` lines: `#rgb`, `#rrggbb`, `#rrggbbaa`, `rgb()`, `rgba()`, another
/// colour by `@name`, and `alpha(@name, a)`. Anything else is skipped.
pub fn parse(css: &str) -> GtkColors {
    let mut raw: Vec<(String, String)> = Vec::new();
    for stmt in css.split(';') {
        let s = strip_comments(stmt);
        let Some(rest) = s.trim().strip_prefix("@define-color") else { continue };
        let rest = rest.trim();
        let Some((name, value)) = rest.split_once(char::is_whitespace) else { continue };
        raw.push((name.trim().to_string(), value.trim().to_string()));
    }
    let mut colors: HashMap<String, Color32> = HashMap::new();
    // References may point at a colour defined later: a few passes settle them.
    for _ in 0..4 {
        for (name, value) in &raw {
            if let Some(c) = colour(value, &colors) {
                colors.insert(name.clone(), c);
            }
        }
    }
    GtkColors { colors }
}

fn strip_comments(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        rest = rest[i + 2..].find("*/").map_or("", |j| &rest[i + 2 + j + 2..]);
    }
    out.push_str(rest);
    out
}

fn colour(v: &str, known: &HashMap<String, Color32>) -> Option<Color32> {
    let v = v.trim();
    if let Some(name) = v.strip_prefix('@') {
        return known.get(name.trim()).copied();
    }
    if let Some(hex) = v.strip_prefix('#') {
        let n = |s: &str| u8::from_str_radix(s, 16).ok();
        let d = |c: char| u8::from_str_radix(&c.to_string(), 16).ok().map(|x| x * 17);
        let c: Vec<char> = hex.chars().collect();
        return match c.len() {
            3 => Some(Color32::from_rgb(d(c[0])?, d(c[1])?, d(c[2])?)),
            6 => Some(Color32::from_rgb(n(&hex[0..2])?, n(&hex[2..4])?, n(&hex[4..6])?)),
            8 => Some(Color32::from_rgba_unmultiplied(n(&hex[0..2])?, n(&hex[2..4])?, n(&hex[4..6])?, n(&hex[6..8])?)),
            _ => None,
        };
    }
    let (func, args) = v.split_once('(')?;
    let args = args.strip_suffix(')')?;
    let parts: Vec<&str> = args.split(',').map(str::trim).collect();
    let byte = |s: &str| -> Option<u8> {
        match s.strip_suffix('%') {
            Some(p) => p.parse::<f32>().ok().map(|p| (p.clamp(0.0, 100.0) * 2.55).round() as u8),
            None => s.parse::<f32>().ok().map(|x| x.clamp(0.0, 255.0).round() as u8),
        }
    };
    let alpha = |s: &str| s.parse::<f32>().ok().map(|a| (a.clamp(0.0, 1.0) * 255.0).round() as u8);
    match (func.trim(), parts.as_slice()) {
        ("rgb", [r, g, b]) => Some(Color32::from_rgb(byte(r)?, byte(g)?, byte(b)?)),
        ("rgba", [r, g, b, a]) => Some(Color32::from_rgba_unmultiplied(byte(r)?, byte(g)?, byte(b)?, alpha(a)?)),
        ("alpha", [c, a]) => {
            let c = colour(c, known)?;
            Some(Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha(a)?))
        }
        _ => None,
    }
}

/// The files a GTK theme's colours are read from, best first.
fn paths() -> Vec<PathBuf> {
    let config =
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    config.map(|c| vec![c.join("gtk-4.0/gtk.css"), c.join("gtk-3.0/gtk.css")]).unwrap_or_default()
}

/// The colours from the first file that defines any, and the times of the files read.
fn read() -> (Option<GtkColors>, Vec<Option<SystemTime>>) {
    let paths = paths();
    let times = paths.iter().map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()).collect();
    let colors = paths.iter().filter_map(|p| std::fs::read_to_string(p).ok()).map(|t| parse(&t)).find(|c| c.dark().is_some());
    (colors, times)
}

static CURRENT: RwLock<Option<GtkColors>> = RwLock::new(None);
static CHANGED: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<()> = OnceLock::new();

/// The GTK theme's colours, once [`enable`]d and if the theme names any.
pub fn current() -> Option<GtkColors> {
    CURRENT.read().ok()?.clone()
}

/// Whether the app follows the GTK theme ([`enable`] was called); tests and tools don't.
pub fn enabled() -> bool {
    STARTED.get().is_some()
}

/// Whether the GTK theme changed since the last call (the interface should be restyled).
pub fn take_changed() -> bool {
    CHANGED.swap(false, Ordering::Relaxed)
}

/// Read the GTK theme now and follow its changes from here on; `ctx` is repainted when it changes.
/// Later calls do nothing.
pub fn enable(ctx: &egui::Context) {
    if STARTED.set(()).is_err() {
        return;
    }
    let (colors, mut times) = read();
    if let Ok(mut c) = CURRENT.write() {
        *c = colors;
    }
    CHANGED.store(true, Ordering::Relaxed);
    let ctx = ctx.clone();
    let spawned = std::thread::Builder::new().name("gtk-theme".into()).spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(1500));
            let now: Vec<Option<SystemTime>> = paths().iter().map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()).collect();
            if now == times {
                continue;
            }
            let (colors, t) = read();
            times = t;
            if let Ok(mut c) = CURRENT.write() {
                if *c == colors {
                    continue;
                }
                *c = colors;
            }
            log::info!("the GTK theme changed: restyling");
            CHANGED.store(true, Ordering::Relaxed);
            ctx.request_repaint();
        }
    });
    if let Err(e) = spawned {
        log::warn!("not following the GTK theme: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_colours_a_theme_defines() {
        let css = "/* generated */\n@define-color accent_color #cba6f7;\n@define-color accent_bg_color @accent_color;\n\
                   @define-color window_bg_color #1e1e2e; @define-color window_fg_color #cdd6f4;\n\
                   @define-color shade_color rgba(0, 0, 0, 0.36);\n@define-color short #fff;\n\
                   @define-color faded alpha(@window_fg_color, 0.5);\n@define-color odd mix(#fff, #000, 0.5);\n\
                   .titlebutton { opacity: 0; }";
        let c = parse(css);
        assert_eq!(c.get("accent_color"), Some(Color32::from_rgb(0xcb, 0xa6, 0xf7)));
        assert_eq!(c.get("accent_bg_color"), c.get("accent_color"));
        assert_eq!(c.get("short"), Some(Color32::WHITE));
        assert_eq!(c.get("shade_color"), Some(Color32::from_rgba_unmultiplied(0, 0, 0, 92)));
        assert_eq!(c.get("faded"), Some(Color32::from_rgba_unmultiplied(0xcd, 0xd6, 0xf4, 128)));
        assert_eq!(c.get("odd"), None);
        assert_eq!(c.dark(), Some(true));
        assert_eq!(parse("@define-color window_bg_color #eff1f5;").dark(), Some(false));
        assert!(parse("window { color: red; }").is_empty());
    }
}
