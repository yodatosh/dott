use colored::*;
use crossterm::{
    cursor,
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind},
    execute, queue,
    terminal::{self, disable_raw_mode, enable_raw_mode, Clear, ClearType, DisableLineWrap, EnableLineWrap},
};
use std::{fs, io::{self, Write}, path::{Path, PathBuf}};

use crate::config::{ALL_TLDS, tld_rank};

// "[✓] .computer" — every cell is padded to the longest supported extension.
const CELL: usize = 4 + 1 + 8;
const GAP: usize = 3;
const BUTTONS: [&str; 3] = ["All", "Clear", "Apply"];

fn path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".dott").join("extensions.json"))
}

/// Saved `/tlds` choice, or None when nothing usable is saved.
pub fn load() -> Option<Vec<&'static str>> {
    match load_at(&path()?) {
        Ok(saved) => saved,
        Err(error) => {
            eprintln!("dott: Ignoring saved extensions (the file was preserved): {error}");
            None
        }
    }
}

fn load_at(path: &Path) -> io::Result<Option<Vec<&'static str>>> {
    let names: Vec<String> = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // Extensions dropped from config.rs are skipped rather than queried.
    let tlds: Vec<_> = ALL_TLDS.iter().copied().filter(|t| names.iter().any(|n| n == t)).collect();
    Ok((!tlds.is_empty()).then_some(tlds))
}

pub fn save(tlds: &[&str]) -> Result<(), String> {
    let path = path().ok_or("Could not save extensions: HOME is not set")?;
    save_at(&path, tlds).map_err(|e| format!("Could not save extensions: {e}"))
}

fn save_at(path: &Path, tlds: &[&str]) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(tlds).map_err(io::Error::other)?;
    let parent = path.parent().ok_or_else(|| io::Error::other("Missing settings directory"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".extensions-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    let _ = fs::remove_file(temporary);
    result
}

pub fn summary(active: Option<&[&str]>) -> String {
    let list = match active {
        Some(tlds) if tlds.len() < ALL_TLDS.len() => tlds.iter().map(|t| format!(".{t}")).collect::<Vec<_>>().join(" "),
        _ => format!("all {}", ALL_TLDS.len()),
    };
    format!("  {}  {}  {}", "extensions".truecolor(80, 80, 100), list.bright_white(), "· /tlds to change".truecolor(80, 80, 100))
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Continue,
    Apply(Vec<&'static str>),
    Cancel,
}

// A clickable span on one rendered line; targets are extension indexes, then the buttons.
struct Region {
    line: usize,
    start: u16,
    end: u16,
    target: usize,
}

struct Selector {
    order: Vec<&'static str>,
    on: Vec<bool>,
    focus: usize,
    cols: usize,
    message: Option<&'static str>,
}

impl Selector {
    fn new(current: &[&str]) -> Self {
        let mut order = ALL_TLDS.to_vec();
        order.sort_by_key(|t| tld_rank(t));
        let on = order.iter().map(|t| current.contains(t)).collect();
        Self { order, on, focus: 0, cols: 1, message: None }
    }

    fn apply_index(&self) -> usize { self.order.len() + 2 }

    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Outcome {
        self.message = None;
        let n = self.order.len();
        let last = self.apply_index();
        let cols = self.cols;
        match code {
            KeyCode::Esc => return Outcome::Cancel,
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => return Outcome::Cancel,
            KeyCode::Enter => return self.apply(),
            KeyCode::Char(' ') => return self.activate(self.focus),
            KeyCode::Right => self.focus = (self.focus + 1).min(last),
            KeyCode::Left => self.focus = self.focus.saturating_sub(1),
            KeyCode::Down if self.focus < n => {
                self.focus = if self.focus + cols < n { self.focus + cols } else { n };
            }
            KeyCode::Up if self.focus >= n => self.focus = (n - 1) / cols * cols,
            KeyCode::Up if self.focus >= cols => self.focus -= cols,
            KeyCode::Tab => self.focus = (self.focus + 1) % (last + 1),
            KeyCode::BackTab => self.focus = (self.focus + last) % (last + 1),
            _ => {}
        }
        Outcome::Continue
    }

    fn click(&mut self, target: usize) -> Outcome {
        self.message = None;
        self.focus = target;
        self.activate(target)
    }

    fn activate(&mut self, target: usize) -> Outcome {
        let n = self.order.len();
        match target {
            t if t < n => self.on[t] = !self.on[t],
            t if t == n => self.on.fill(true),
            t if t == n + 1 => self.on.fill(false),
            _ => return self.apply(),
        }
        Outcome::Continue
    }

    fn apply(&mut self) -> Outcome {
        let chosen: Vec<_> = self.order.iter().zip(&self.on).filter(|(_, on)| **on).map(|(t, _)| *t).collect();
        if chosen.is_empty() {
            self.message = Some("select at least one extension");
            return Outcome::Continue;
        }
        Outcome::Apply(chosen)
    }

    // Reflows the grid for the current width and returns the lines plus their click targets.
    fn layout(&mut self, width: u16) -> (Vec<String>, Vec<Region>) {
        let n = self.order.len();
        self.cols = ((width as usize).saturating_sub(2) + GAP) / (CELL + GAP);
        self.cols = self.cols.clamp(1, n);
        let selected = self.on.iter().filter(|on| **on).count();
        let mut lines = vec![
            format!("  {} {}", "Choose extensions ·".truecolor(110, 110, 140), format!("{selected} selected").bright_white()),
            String::new(),
        ];
        let mut regions = Vec::new();
        let style = |text: String, target: usize, focus: usize| {
            if target == focus { text.bright_white().bold().reversed().to_string() } else { text.truecolor(170, 170, 190).to_string() }
        };
        for (row, chunk) in self.order.chunks(self.cols).enumerate() {
            let mut line = String::from("  ");
            for (col, tld) in chunk.iter().enumerate() {
                let index = row * self.cols + col;
                let start = 2 + col * (CELL + GAP);
                let mark = if self.on[index] { "✓".bright_green().bold().to_string() } else { " ".into() };
                let name = format!(".{tld:<8}");
                line.push_str(&style("[".into(), index, self.focus));
                line.push_str(&mark);
                line.push_str(&style(format!("] {name}"), index, self.focus));
                line.push_str(&" ".repeat(GAP));
                regions.push(Region { line: lines.len(), start: start as u16, end: (start + CELL) as u16, target: index });
            }
            lines.push(line.trim_end().to_string());
        }
        lines.push(String::new());
        let mut line = String::from("  ");
        let mut start = 2;
        for (i, label) in BUTTONS.iter().enumerate() {
            let text = format!("[{label}]");
            regions.push(Region { line: lines.len(), start: start as u16, end: (start + text.len()) as u16, target: n + i });
            start += text.len() + 2;
            line.push_str(&style(text, n + i, self.focus));
            line.push_str("  ");
        }
        lines.push(line);
        lines.push(String::new());
        let hint = |s: &str| format!("  {}", s.truecolor(80, 80, 100));
        match self.message {
            Some(message) => lines.push(format!("  {}", message.truecolor(220, 170, 60))),
            None => lines.push(hint("arrows: move · space/click: toggle")),
        }
        lines.push(hint("enter: apply · esc: cancel"));
        (lines, regions)
    }
}

fn target_at(regions: &[Region], line: usize, column: u16) -> Option<usize> {
    regions.iter().find(|r| r.line == line && (r.start..r.end).contains(&column)).map(|r| r.target)
}

// Restores the terminal on every exit from the selector, including errors and panics.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture, EnableLineWrap, cursor::Show);
        let _ = disable_raw_mode();
    }
}

/// Opens the selector below the prompt. Returns None when cancelled.
pub fn select(current: &[&str]) -> io::Result<Option<Vec<&'static str>>> {
    let mut selector = Selector::new(current);
    let mut out = io::stdout();
    enable_raw_mode()?;
    let _restore = Restore;
    execute!(out, EnableMouseCapture, DisableLineWrap, cursor::Hide)?;
    let mut origin = cursor::position()?.1;

    let outcome = loop {
        let (width, height) = terminal::size()?;
        let (lines, regions) = selector.layout(width);
        let visible = (lines.len() as u16).min(height);
        // Make room by scrolling when the selector would run past the bottom of the window.
        if origin + visible > height {
            queue!(out, cursor::MoveTo(0, height.saturating_sub(1)))?;
            for _ in 0..origin + visible - height { writeln!(out)?; }
            origin = height - visible;
        }
        queue!(out, cursor::MoveTo(0, origin), Clear(ClearType::FromCursorDown))?;
        for (i, line) in lines.iter().take(visible as usize).enumerate() {
            queue!(out, cursor::MoveTo(0, origin + i as u16))?;
            write!(out, "{line}")?;
        }
        out.flush()?;

        let outcome = match event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => selector.key(key.code, key.modifiers),
            Event::Mouse(mouse) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                let target = mouse.row.checked_sub(origin)
                    .and_then(|line| target_at(&regions, line as usize, mouse.column));
                match target {
                    Some(target) => selector.click(target),
                    None => Outcome::Continue,
                }
            }
            Event::Resize(_, rows) => {
                origin = origin.min(rows.saturating_sub(1));
                Outcome::Continue
            }
            _ => Outcome::Continue,
        };
        match outcome {
            Outcome::Continue => continue,
            Outcome::Apply(chosen) => break Some(chosen),
            Outcome::Cancel => break None,
        }
    };

    execute!(out, cursor::MoveTo(0, origin), Clear(ClearType::FromCursorDown))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lines before the grid: title and a blank line.
    const GRID_TOP: usize = 2;

    fn none() -> KeyModifiers { KeyModifiers::NONE }

    #[test]
    fn keyboard_navigation_follows_the_grid_and_reaches_buttons() {
        let mut s = Selector::new(&["com"]);
        s.layout((2 + 3 * (CELL + GAP)) as u16); // three columns
        assert_eq!(s.cols, 3);
        assert_eq!(s.order[..3], ["com", "io", "dev"]);
        s.key(KeyCode::Down, none());
        assert_eq!(s.focus, 3);
        s.key(KeyCode::Up, none());
        s.key(KeyCode::Up, none());
        assert_eq!(s.focus, 0);
        s.key(KeyCode::Left, none());
        assert_eq!(s.focus, 0);
        for _ in 0..10 { s.key(KeyCode::Down, none()); }
        assert_eq!(s.focus, s.order.len(), "down from the last row lands on All");
        s.key(KeyCode::Up, none());
        assert_eq!(s.focus, (s.order.len() - 1) / 3 * 3);
        s.key(KeyCode::BackTab, none());
        s.key(KeyCode::Tab, none());
        assert_eq!(s.focus, (s.order.len() - 1) / 3 * 3);
    }

    #[test]
    fn space_toggles_and_buttons_select_all_or_clear() {
        let mut s = Selector::new(&["com"]);
        s.layout(80);
        s.key(KeyCode::Right, none());
        s.key(KeyCode::Char(' '), none());
        assert_eq!(s.key(KeyCode::Enter, none()), Outcome::Apply(vec!["com", "io"]));
        let all = s.order.len();
        assert_eq!(s.click(all), Outcome::Continue);
        assert!(s.on.iter().all(|on| *on));
        s.click(all + 1);
        assert!(s.on.iter().all(|on| !*on));
    }

    #[test]
    fn empty_selection_cannot_be_applied_and_cancel_discards_changes() {
        let mut s = Selector::new(&["com"]);
        s.layout(80);
        s.key(KeyCode::Char(' '), none());
        assert_eq!(s.key(KeyCode::Enter, none()), Outcome::Continue);
        assert!(s.message.is_some());
        assert_eq!(s.click(s.apply_index()), Outcome::Continue);
        assert_eq!(s.key(KeyCode::Esc, none()), Outcome::Cancel);
        assert_eq!(s.key(KeyCode::Char('c'), KeyModifiers::CONTROL), Outcome::Cancel);
    }

    #[test]
    fn clicks_map_to_cells_after_resizing() {
        let mut s = Selector::new(&[]);
        let (_, wide) = s.layout(120);
        let cols = s.cols;
        assert!(cols > 3);
        assert_eq!(target_at(&wide, GRID_TOP, 2), Some(0));
        assert_eq!(target_at(&wide, GRID_TOP, (2 + CELL + GAP) as u16), Some(1));
        assert_eq!(target_at(&wide, GRID_TOP + 1, 2), Some(cols));
        assert_eq!(target_at(&wide, GRID_TOP, (2 + CELL) as u16), None, "gap between cells");

        let (lines, narrow) = s.layout(20);
        assert_eq!(s.cols, 1);
        assert_eq!(target_at(&narrow, GRID_TOP + 1, 2), Some(1));
        let buttons = GRID_TOP + s.order.len() + 1;
        assert_eq!(target_at(&narrow, buttons, 2), Some(s.order.len()));
        assert_eq!(target_at(&narrow, buttons, 9), Some(s.order.len() + 1));
        assert_eq!(target_at(&narrow, buttons, 18), Some(s.apply_index()));
        assert_eq!(lines.len(), buttons + 4);
    }

    #[test]
    fn saved_extensions_round_trip_and_bad_files_are_preserved() {
        let dir = std::env::temp_dir().join(format!("dott-extensions-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let file = dir.join(".dott").join("extensions.json");
        assert_eq!(load_at(&file).unwrap(), None);
        save_at(&file, &["io", "com"]).unwrap();
        assert_eq!(load_at(&file).unwrap(), Some(vec!["com", "io"]));
        fs::write(&file, br#"["retired", "bot"]"#).unwrap();
        assert_eq!(load_at(&file).unwrap(), Some(vec!["bot"]));
        fs::write(&file, br#"["retired"]"#).unwrap();
        assert_eq!(load_at(&file).unwrap(), None);
        fs::write(&file, b"not json").unwrap();
        assert!(load_at(&file).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"not json");
        fs::remove_dir_all(dir).unwrap();
    }
}
