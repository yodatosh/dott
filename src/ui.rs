use colored::*;
use crossterm::{
    cursor, event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyModifiers},
    execute, queue,
    terminal::{self, Clear, ClearType, DisableLineWrap, EnableLineWrap},
};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{io::{self, Write}, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use crate::{model::{Availability, UnknownReason, ProtectionReason}, pricing::Catalog};

pub type Results = Vec<(String, Availability)>;

// Result rows as in the classic CLI: "  ✓  domain  details".
const RESULT_NAME_COL: usize = 5;
const META_GAP: &str = "  ";

pub fn content_width(columns: u16) -> usize { columns.saturating_sub(1) as usize }

static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

// Interactive sessions keep the prompt on the last row; output uses the rows above.
fn dock_rows(rows: u16) -> u16 {
    if SESSION_ACTIVE.load(Ordering::Relaxed) && rows >= 3 { 1 } else { 0 }
}

pub(crate) fn output_size() -> io::Result<(u16, u16)> {
    let (columns, rows) = terminal::size()?;
    Ok((columns, rows - dock_rows(rows)))
}

// Opening pushes the shell's earlier output into scrollback, so dott starts on a
// clean window. Output is ordinary terminal text above the bottom prompt row.
pub struct Session;
impl Session {
    pub fn enter() -> io::Result<Self> {
        let (_, rows) = terminal::size()?;
        let mut out = io::stdout();
        for _ in 0..rows { write!(out, "\r\n")?; }
        queue!(out, cursor::MoveTo(0, 0))?;
        out.flush()?;
        SESSION_ACTIVE.store(true, Ordering::Relaxed);
        Ok(Self)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        SESSION_ACTIVE.store(false, Ordering::Relaxed);
        let mut out = io::stdout();
        if let Ok((_, rows)) = terminal::size() { let _ = queue!(out, cursor::MoveTo(0, rows.saturating_sub(1))); }
        let _ = execute!(out, DisableBracketedPaste, EnableLineWrap, cursor::Show);
        let _ = writeln!(out, "\r");
        let _ = terminal::disable_raw_mode();
    }
}

pub fn width() -> usize { terminal::size().map(|(w, _)| w as usize).unwrap_or(80) }

// All result data is validated ASCII. UI symbols occupy one terminal cell.
pub fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width { return text.into(); }
    if width == 0 { return String::new(); }
    text.chars().take(width - 1).chain(std::iter::once('…')).collect()
}

// The classic CLI banner: gradient logo, version, and a short instruction.
pub fn banner() -> Vec<String> {
    vec![
        String::new(),
        "   ____       _   _ ".truecolor(255, 155, 0).to_string(),
        "  |  _ \\  ___| |_| |_".truecolor(255, 60, 90).to_string(),
        "  | | | |/ _ \\ __| __|".truecolor(180, 50, 230).to_string(),
        "  | |_| | (_) | |_| |_".truecolor(80, 130, 255).to_string(),
        format!("  |____/ \\___/ \\__|\\__|  v{}", env!("CARGO_PKG_VERSION")).truecolor(50, 215, 235).to_string(),
        String::new(),
        "  private domain search..".truecolor(80, 80, 110).to_string(),
        "  type a name and hit enter. /help for commands · esc to quit.".truecolor(110, 105, 140).to_string(),
        String::new(),
    ]
}

pub fn row(domain: &str, status: Option<&Availability>, pad: usize, prices: &Catalog, width: usize, frame: usize) -> String {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let symbol = match status {
        Some(Availability::Available) => "✓".bright_green().bold(),
        Some(Availability::Taken(_)) => "✗".truecolor(70, 70, 90),
        Some(Availability::Protected(_)) => "★".bright_yellow().bold(),
        Some(Availability::Unknown(_)) => "?".bright_yellow(),
        None => FRAMES[frame % FRAMES.len()].truecolor(160, 120, 220),
    };
    let prefix = "  ";
    let gap = " ".repeat(RESULT_NAME_COL.saturating_sub(prefix.len() + 1));
    let budget = width.saturating_sub(RESULT_NAME_COL + 1);
    if width < RESULT_NAME_COL + 1 { return clip(domain, width); }
    let name = clip(domain, budget);
    let padded = format!("{name:<pad$}", pad = pad.min(budget).max(name.chars().count()));
    let spare = budget.saturating_sub(padded.chars().count());
    if let Some(Availability::Taken(dates)) = status {
        // reg/upd/exp as in the classic CLI; expiry is colored by how soon it is.
        // Narrow rows drop reg/upd first, then the expiry, never a partial date.
        let mut history = String::new();
        if let Some(date) = &dates.registered { history.push_str(&format!("  reg {date}")); }
        if let Some(date) = &dates.updated { history.push_str(&format!("  upd {date}")); }
        let expiry = dates.expires.as_ref().map(|date| format!("  exp {date}")).unwrap_or_default();
        let (history, expiry) = [(history.as_str(), expiry.as_str()), ("", expiry.as_str()), ("", "")].into_iter()
            .find(|(h, e)| h.chars().count() + e.chars().count() <= spare).unwrap_or(("", ""));
        let expiry_color = match dates.expires.as_deref().and_then(crate::utils::days_until) {
            Some(days) if days < 90 => (220, 100, 60),
            Some(days) if days < 365 => (200, 170, 60),
            _ => (110, 100, 150),
        };
        let history = history.truecolor(110, 100, 150);
        let expiry = expiry.truecolor(expiry_color.0, expiry_color.1, expiry_color.2);
        return format!("{prefix}{symbol}{gap}{}{history}{expiry}", padded.truecolor(60, 60, 80));
    }
    const PREMIUM: &str = "⚠ likely premium";
    // The premium warning stays separate from the price so each keeps its own color.
    let (metadata, warning) = match status {
        Some(Availability::Available) => {
            let premium = crate::config::is_likely_premium(domain);
            match prices.listing_price(domain) {
                Some(quote) if premium && format!("{META_GAP}{quote} · {PREMIUM}").chars().count() <= spare => (format!("{META_GAP}{quote} · "), PREMIUM),
                Some(quote) if !premium => (format!("{META_GAP}{quote}"), ""),
                _ if premium => (META_GAP.into(), PREMIUM),
                _ => (String::new(), ""),
            }
        }
        Some(Availability::Protected(reason)) => (format!("{META_GAP}{}", reason.label()), ""),
        Some(Availability::Unknown(reason)) => (format!("{META_GAP}{}", reason.label()), ""),
        _ => (String::new(), ""),
    };
    // Omit secondary details rather than displaying a partial price or date.
    let (metadata, warning) = if metadata.chars().count() + warning.chars().count() <= spare { (metadata, warning) } else { (String::new(), "") };
    let (name_color, meta_color) = match status {
        Some(Availability::Protected(_)) => ((60, 60, 80), (80, 80, 100)),
        Some(Availability::Unknown(_)) => ((100, 100, 80), (100, 100, 80)),
        _ => ((80, 80, 100), (80, 80, 100)),
    };
    let styled_name = if matches!(status, Some(Availability::Available)) { padded.bright_white().bold() }
        else { padded.truecolor(name_color.0, name_color.1, name_color.2) };
    let styled_metadata = if matches!(status, Some(Availability::Available)) {
        let warning = if warning.is_empty() { String::new() } else { warning.truecolor(220, 170, 60).to_string() };
        format!("{}{warning}", metadata.truecolor(100, 210, 210))
    } else { metadata.truecolor(meta_color.0, meta_color.1, meta_color.2).to_string() };
    format!("{prefix}{symbol}{gap}{styled_name}{styled_metadata}")
}

pub fn price_notice(results: &Results, prices: &Catalog) -> Option<&'static str> {
    if !results.iter().any(|(domain, status)| matches!(status, Availability::Available) && prices.quote(domain).is_none()) { return None; }
    Some(if prices.refreshing() { "fetching prices…" } else { "Some price estimates are unavailable." })
}

pub fn retry_hint(results: &Results) -> Option<String> {
    let count = results.iter().filter(|(_, status)| matches!(status, Availability::Unknown(_))).count();
    match count {
        0 => None,
        1 => Some("/retry to check that domain again".into()),
        count => Some(format!("/retry to check those {count} again")),
    }
}

pub fn details(domain: &str, status: &Availability, prices: &Catalog) -> Vec<String> {
    let mut lines = vec![domain.into(), format!("Status: {}", status.as_str())];
    if let Availability::Protected(reason) = status {
        lines.push(format!("Protection: {}", reason.label()));
        if *reason == ProtectionReason::Trademark {
            lines.push("A matching DPML trademark-protection record was found.".into());
            lines.push("Coverage and exceptions depend on the registry and registrar.".into());
        }
    }
    if let Availability::Taken(dates) = status {
        for (label, value) in [("Registered", &dates.registered), ("Updated", &dates.updated), ("Expires", &dates.expires)] {
            if let Some(date) = value { lines.push(format!("{label}: {date}")); }
        }
        if let Some(days) = dates.expires.as_deref().and_then(crate::utils::days_until) {
            lines.push(format!("Expiry {} days from today; not a release date.", days));
        }
    }
    if matches!(status, Availability::Available) {
        if let Some(quote) = prices.quote(domain) { lines.push(format!("Estimate: {quote} on Porkbun")); }
        if crate::config::is_likely_premium(domain) {
            lines.push("Possibly premium: the standard catalog estimate may not apply.".into());
        }
        lines.push("Registry availability is not a checkout guarantee.".into());
    }
    if let Availability::Unknown(reason) = status {
        lines.push(format!("Reason: {}", reason.label()));
        lines.push("Use /retry to check inconclusive results again.".into());
    }
    lines
}

struct Restore;
impl Restore {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let restore = Self;
        execute!(io::stdout(), EnableBracketedPaste, DisableLineWrap)?;
        Ok(restore)
    }
}
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableBracketedPaste, EnableLineWrap, cursor::Show);
        let _ = terminal::disable_raw_mode();
    }
}

// Live checks repaint their rows in place above the prompt row. Finished output is
// ordinary terminal text, so native selection and scrollback remain available.
pub struct Panel {
    domains: Vec<String>,
    rows: Vec<Option<Availability>>,
    origin: u16,
    size: (u16, u16),
    offset: usize,
    visible: usize,
    shown: usize,
}

fn search_lines(domains: &[String], rows: &[Option<Availability>], prices: &Catalog,
    offset: usize, visible: usize, width: usize, height: usize, frame: usize) -> Vec<String> {
    let total = domains.len();
    let mut lines = Vec::new();
    let pad = domains.iter().map(String::len).max().unwrap_or(0);
    for i in offset..(offset + visible).min(total) {
        lines.push(row(&domains[i], rows[i].as_ref(), pad, prices, width, frame));
    }
    if visible < total {
        let hint = format!("  ↑/↓ scroll · {}–{}/{total} · esc cancel", offset + 1, (offset + visible).min(total));
        lines.push(clip(&hint, width).truecolor(80, 80, 100).to_string());
    }
    lines.truncate(height.max(1));
    lines
}

impl Panel {
    fn new(domains: Vec<String>) -> io::Result<Self> {
        let size = output_size()?;
        let origin = cursor::position()?.1;
        let mut panel = Self { rows: vec![None; domains.len()], domains, origin, size, offset: 0, visible: 0, shown: 0 };
        panel.reflow()?;
        Ok(panel)
    }

    fn reflow(&mut self) -> io::Result<()> {
        let mut out = io::stdout();
        let actual = terminal::size()?;
        // A resize can leave the old prompt row inside the output area.
        for y in self.size.1..actual.1.min(self.size.1.saturating_add(1)) {
            queue!(out, cursor::MoveTo(0, y), Clear(ClearType::CurrentLine))?;
        }
        self.size = output_size()?;
        for y in 0..self.shown {
            if self.origin as usize + y < self.size.1 as usize {
                queue!(out, cursor::MoveTo(0, self.origin + y as u16), Clear(ClearType::CurrentLine))?;
            }
        }
        self.visible = self.domains.len().min((self.size.1 as usize).saturating_sub(2).max(1));
        self.offset = self.offset.min(self.domains.len().saturating_sub(self.visible));
        self.origin = self.origin.min(actual.1.saturating_sub(1));
        let reserved = (self.visible + 2).min(self.size.1.max(1) as usize);
        let overflow = (self.origin as usize + reserved).saturating_sub(self.size.1 as usize);
        if overflow > 0 {
            queue!(out, cursor::MoveTo(0, actual.1.saturating_sub(1)))?;
            for _ in 0..overflow { write!(out, "\r\n")?; }
            out.flush()?;
            self.origin = self.origin.saturating_sub(overflow as u16);
        }
        out.flush()?;
        busy_dock()
    }

    pub fn finish(&mut self, results: &Results, prices: &Catalog, changes: Vec<String>, cancelled: bool) -> io::Result<()> {
        clear_dock()?;
        execute!(io::stdout(), cursor::MoveTo(0, self.origin))?;
        print_results(results, prices, &changes, cancelled)
    }

    fn paint(&mut self, prices: &Catalog, frame: usize) -> io::Result<()> {
        if output_size()? != self.size { self.reflow()?; }
        let width = content_width(self.size.0);
        let lines = search_lines(&self.domains, &self.rows, prices, self.offset, self.visible, width,
            self.size.1.max(1) as usize, frame);
        let mut out = io::stdout();
        for (y, line) in lines.iter().enumerate().take(self.size.1.max(1) as usize) {
            queue!(out, cursor::MoveTo(0, self.origin + y as u16), Clear(ClearType::CurrentLine))?;
            write!(out, "{line}")?;
        }
        self.shown = lines.len();
        out.flush()
    }
}

pub fn print_results(results: &Results, prices: &Catalog, changes: &[String], cancelled: bool) -> io::Result<()> {
    let width = width().saturating_sub(1);
    let pad = results.iter().map(|(d, _)| d.len()).max().unwrap_or(0);
    let mut lines = Vec::new();
    lines.extend(results.iter().map(|(domain, status)| row(domain, Some(status), pad, prices, width, 0)));
    lines.push(String::new());
    let available = results.iter().filter(|(_, status)| matches!(status, Availability::Available)).count();
    let summary = format!("  {available} available  ·  {} checked", results.len());
    lines.push(if summary.chars().count() <= width {
        format!("  {} available  ·  {} checked", available.to_string().bright_green().bold(),
            results.len().to_string().truecolor(80, 80, 100))
    } else { clip(&summary, width).truecolor(80, 80, 100).to_string() });
    if let Some(notice) = price_notice(results, prices) {
        lines.push(clip(&format!("  {notice}"), width).truecolor(80, 80, 100).to_string());
    }
    for domain in changes { lines.push(clip(&format!("  {domain} · taken since your last check"), width).truecolor(220, 150, 120).to_string()); }
    if cancelled {
        lines.push(clip("  Cancelled · unfinished checks are inconclusive", width).truecolor(80, 80, 100).to_string());
    }
    if let Some(hint) = retry_hint(results) {
        lines.push(clip(&format!("  {hint}"), width).truecolor(220, 170, 60).to_string());
    }
    // Dark closing rule. Fixed length, so narrowing the window doesn't rewrap it.
    lines.push(clip(&format!("  {}", "─".repeat(53)), width).truecolor(38, 36, 52).to_string());
    lines.push(String::new());
    let mut out = io::stdout();
    for line in lines {
        queue!(out, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        write!(out, "{line}\r\n")?;
    }
    out.flush()
}

#[derive(Default)]
struct Editor {
    text: Vec<char>, cursor: usize, history_index: Option<usize>, draft: Vec<char>,
    // Set when esc just cleared typed text, so the next esc quits.
    quit_armed: bool,
}
impl Editor {
    fn insert(&mut self, text: &str) {
        // Bracketed multiline paste stays one editable input, never submits commands.
        for c in text.chars().take(4096usize.saturating_sub(self.text.len())) {
            if c.is_control() && !c.is_whitespace() { continue; }
            self.text.insert(self.cursor, if c.is_whitespace() { ' ' } else { c });
            self.cursor += 1;
        }
    }
    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers, history: &[String]) {
        match code {
            KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => { self.text.clear(); self.cursor = 0; }
            KeyCode::Char('k') if modifiers.contains(KeyModifiers::CONTROL) => self.text.truncate(self.cursor),
            KeyCode::Char('w') if modifiers.contains(KeyModifiers::CONTROL) => {
                let end = self.cursor;
                while self.cursor > 0 && self.text[self.cursor - 1].is_whitespace() { self.cursor -= 1; }
                while self.cursor > 0 && !self.text[self.cursor - 1].is_whitespace() { self.cursor -= 1; }
                self.text.drain(self.cursor..end);
            }
            KeyCode::Char('a') if modifiers.contains(KeyModifiers::CONTROL) => self.cursor = 0,
            KeyCode::Char('e') if modifiers.contains(KeyModifiers::CONTROL) => self.cursor = self.text.len(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.text.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Backspace if self.cursor > 0 => { self.cursor -= 1; self.text.remove(self.cursor); }
            KeyCode::Delete if self.cursor < self.text.len() => { self.text.remove(self.cursor); }
            KeyCode::Up if !history.is_empty() => {
                let index = match self.history_index { Some(i) => i.saturating_sub(1), None => { self.draft = self.text.clone(); history.len() - 1 } };
                self.history_index = Some(index);
                self.text = history[index].chars().collect();
                self.cursor = self.text.len();
            }
            KeyCode::Down => {
                if let Some(i) = self.history_index {
                    if i + 1 < history.len() { self.history_index = Some(i + 1); self.text = history[i + 1].chars().collect(); }
                    else { self.history_index = None; self.text = self.draft.clone(); }
                    self.cursor = self.text.len();
                }
            }
            KeyCode::Char(c) if !modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => self.insert(&c.to_string()),
            _ => {}
        }
    }
    fn visible(&self, cells: usize) -> (String, usize) {
        let start = self.cursor.saturating_sub(cells.saturating_sub(1));
        // Domain input is ASCII. Other characters use a single-cell placeholder
        // while editing; the original input is retained for validation on submit.
        (self.text.iter().skip(start).take(cells).map(|c| if c.is_ascii() { *c } else { '?' }).collect(), self.cursor - start)
    }
}

struct ComposerFrame {
    lines: Vec<String>,
    cursor: (usize, usize),
}

// Plan the command menu and the bottom prompt row before drawing.
fn composer_frame(suggestions: &crate::commands::Suggestions, prompt: &str, editor: &Editor,
    columns: u16, height: u16) -> ComposerFrame {
    let width = content_width(columns);
    let capacity = (height.max(1) as usize).saturating_sub(1);
    let options = suggestions.options();
    let visible = if capacity < 2 { 0 } else { options.len().min(capacity - 1).min(6) };
    let selected = suggestions.selected_index();
    let start = selected.saturating_sub(visible.saturating_sub(1)).min(options.len().saturating_sub(visible));
    let mut lines = Vec::new();
    for (index, command) in options.iter().enumerate().skip(start).take(visible) {
        let text = if width >= 50 {
            format!("    {} {:<18} {}", if index == selected { "›" } else { " " }, command.usage(), command.description)
        } else { format!("    {} {}", if index == selected { "›" } else { " " }, command.usage()) };
        let text = clip(&text, width);
        lines.push(if index == selected { text.bright_white().bold().to_string() } else { text.truecolor(110, 110, 140).to_string() });
    }
    if visible > 0 {
        let hint = if width >= 55 { format!("    ↑/↓ choose · enter select · tab complete · {}–{}/{}", start + 1, start + visible, options.len()) }
            else { "    ↑/↓ · enter · esc".into() };
        lines.push(clip(&hint, width).truecolor(80, 80, 100).to_string());
    } else if editor.quit_armed && capacity > 0 {
        lines.push(clip("    esc again to quit", width).truecolor(80, 80, 100).to_string());
    }
    let input_col = if width > prompt_width(prompt) { prompt_width(prompt) } else { 0 };
    let cells = width - input_col;
    let (text, caret) = editor.visible(cells.max(1));
    lines.push(format!("{}{}", if input_col > 0 { prompt } else { "" }, clip(&text, cells)));
    let row = lines.len() - 1;
    ComposerFrame { lines, cursor: ((input_col + caret).min(width.saturating_sub(1)), row) }
}

pub(crate) fn clear_dock() -> io::Result<()> {
    let (_, rows) = terminal::size()?;
    let mut out = io::stdout();
    for y in rows - dock_rows(rows)..rows {
        queue!(out, cursor::MoveTo(0, y), Clear(ClearType::CurrentLine))?;
    }
    out.flush()
}

// While a search or the extension picker runs, the prompt row shows a dim prompt.
pub(crate) fn busy_dock() -> io::Result<()> {
    let (_, rows) = terminal::size()?;
    if dock_rows(rows) == 0 { return Ok(()); }
    let mut out = io::stdout();
    queue!(out, cursor::Hide, cursor::MoveTo(0, rows - 1), Clear(ClearType::CurrentLine))?;
    write!(out, "{}", "  ❯❯❯".truecolor(80, 80, 100))?;
    out.flush()
}

#[derive(Default)]
struct CommandMenuView {
    // First row of the drawn menu + prompt block; the prompt is its last row.
    anchor: Option<u16>,
    shown: usize,
    // Where the next output line goes, above the prompt.
    output_cursor: Option<(u16, u16)>,
    // Last drawn layout: each line's width and the caret (column, line).
    cells: Vec<usize>,
    caret: (usize, usize),
}

// Row where the previously drawn block starts after a resize. Reflowing
// terminals wrap rows that no longer fit; assume that only when the rows below
// the caret confirm it, so output above the block is never cleared.
fn composer_top(cells: &[usize], caret: (usize, usize), columns: u16, rows: u16, now: u16) -> u16 {
    let span = |width: &usize| (*width).max(1).div_ceil(columns.max(1) as usize);
    let (column, line) = caret;
    let segment = column / columns.max(1) as usize;
    let below = cells.get(line).map_or(1, span).saturating_sub(1 + segment) + cells.iter().skip(line + 1).map(span).sum::<usize>();
    let reflowed = rows.saturating_sub(1).saturating_sub(now) as usize == below;
    let above = if reflowed { cells.iter().take(line).map(span).sum::<usize>() + segment } else { line };
    now.saturating_sub(above as u16)
}

impl CommandMenuView {
    fn erase(&self, rows: std::ops::Range<u16>) -> io::Result<()> {
        let height = terminal::size()?.1;
        let mut out = io::stdout();
        for row in rows.start..rows.end.min(height) {
            queue!(out, cursor::MoveTo(0, row), Clear(ClearType::CurrentLine))?;
        }
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        let Some(anchor) = self.anchor else { return Ok(()); };
        self.erase(anchor..anchor.saturating_add(self.shown as u16))?;
        let height = terminal::size()?.1;
        let (x, y) = self.output_cursor.unwrap_or((0, anchor));
        self.shown = 0;
        self.anchor = None;
        execute!(io::stdout(), cursor::MoveTo(x, y.min(height.saturating_sub(1))))
    }

    // Resizing moves existing lines. Follow the caret to find the old block,
    // then clear it so the next draw doesn't overwrite or strand output.
    fn follow_resize(&mut self) -> io::Result<()> {
        let (Some(anchor), Some((x, y))) = (self.anchor, self.output_cursor) else { return Ok(()); };
        let (Ok((_, now)), Ok((columns, rows))) = (cursor::position(), terminal::size()) else { return Ok(()); };
        let top = composer_top(&self.cells, self.caret, columns, rows, now);
        self.output_cursor = Some((x, top.saturating_sub(anchor.saturating_sub(y))));
        self.anchor = None;
        self.shown = 0;
        execute!(io::stdout(), cursor::MoveTo(0, top), Clear(ClearType::FromCursorDown))
    }

    fn submit(&mut self, prompt: &str, input: &str) -> io::Result<()> {
        self.clear()?;
        let mut out = io::stdout();
        // The echoed query belongs to the output area, never the prompt row.
        let (_, limit) = output_size()?;
        let (_, y) = cursor::position()?;
        if limit > 0 && y >= limit {
            queue!(out, cursor::MoveTo(0, terminal::size()?.1.saturating_sub(1)))?;
            for _ in 0..=(y - limit) { write!(out, "\r\n")?; }
            queue!(out, cursor::MoveTo(0, limit - 1))?;
        }
        let cells = width().saturating_sub(prompt_width(prompt) + 1);
        let text: String = input.chars().map(|c| if c.is_ascii() { c } else { '?' }).collect();
        write!(out, "{prompt}{}\r\n", clip(&text, cells))?;
        out.flush()
    }

    fn draw(&mut self, suggestions: &crate::commands::Suggestions, prompt: &str, editor: &Editor) -> io::Result<()> {
        let (columns, height) = terminal::size()?;
        let frame = composer_frame(suggestions, prompt, editor, columns, height);
        if self.output_cursor.is_none() { self.output_cursor = Some(cursor::position()?); }
        let anchor = height.saturating_sub(frame.lines.len() as u16);
        let (x, y) = self.output_cursor.unwrap();
        let y = y.min(height.saturating_sub(1));
        // Scroll output up when the block would cover it.
        let overflow = y.saturating_sub(anchor);
        let mut out = io::stdout();
        queue!(out, cursor::Hide)?;
        if let Some(old_anchor) = self.anchor {
            self.erase(old_anchor..old_anchor.saturating_add(self.shown as u16))?;
        }
        if overflow > 0 {
            queue!(out, cursor::MoveTo(0, height.saturating_sub(1)))?;
            for _ in 0..overflow { write!(out, "\r\n")?; }
        }
        self.output_cursor = Some((x.min(columns.saturating_sub(1)), y.saturating_sub(overflow)));
        self.anchor = Some(anchor);
        for (i, line) in frame.lines.iter().enumerate() {
            let row = anchor as usize + i;
            if row >= height as usize { break; }
            queue!(out, cursor::MoveTo(0, row as u16), Clear(ClearType::CurrentLine))?;
            write!(out, "{line}")?;
        }
        self.shown = frame.lines.len();
        self.cells = frame.lines.iter().map(|line| prompt_width(line)).collect();
        self.caret = frame.cursor;
        queue!(out, cursor::MoveTo(frame.cursor.0 as u16, anchor.saturating_add(frame.cursor.1 as u16)), cursor::Show)?;
        out.flush()
    }
}

// Prompt colors are ANSI SGR sequences and occupy no terminal cells.
pub(crate) fn prompt_width(prompt: &str) -> usize {
    let mut escape = false;
    prompt.chars().filter(|c| {
        if *c == '\u{1b}' { escape = true; return false; }
        if escape { if *c == 'm' { escape = false; } return false; }
        true
    }).count()
}

impl Drop for CommandMenuView {
    fn drop(&mut self) { let _ = self.clear(); }
}

pub fn read_input(prompt: &str, history: &mut Vec<String>) -> io::Result<Option<String>> {
    let _restore = Restore::enter()?;
    let mut editor = Editor::default();
    let mut suggestions = crate::commands::Suggestions::default();
    let mut menu = CommandMenuView::default();
    loop {
        suggestions.update(&editor.text.iter().collect::<String>());
        // Recalling a command must keep ↑/↓ as history navigation. Suggestions
        // reopen when the recalled text is edited, not merely recalled.
        if editor.history_index.is_some() { suggestions.dismiss(); }
        menu.draw(&suggestions, prompt, &editor)?;
        let event = event::read()?;
        editor.quit_armed = false;
        match event {
            Event::Key(key) if key.kind != event::KeyEventKind::Release => match key.code {
                KeyCode::Esc if !suggestions.options().is_empty() => suggestions.dismiss(),
                KeyCode::Esc if !editor.text.is_empty() => {
                    editor.text.clear();
                    editor.cursor = 0;
                    editor.history_index = None;
                    editor.quit_armed = true;
                    continue;
                }
                KeyCode::Esc => { menu.clear()?; print!("\r\n"); return Ok(None); }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { menu.clear()?; print!("\r\n"); return Ok(None); }
                KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) && editor.text.is_empty() => { menu.clear()?; print!("\r\n"); return Ok(None); }
                KeyCode::Up if !suggestions.options().is_empty() => suggestions.move_by(-1),
                KeyCode::Down if !suggestions.options().is_empty() => suggestions.move_by(1),
                KeyCode::Tab => {
                    if let Some(command) = suggestions.current() {
                        editor.text = command.completion().chars().collect();
                        editor.cursor = editor.text.len();
                        editor.history_index = None;
                        suggestions.update(&editor.text.iter().collect::<String>());
                        suggestions.dismiss();
                    }
                }
                KeyCode::Enter => {
                    if let Some(command) = suggestions.current() {
                        editor.text = command.completion().chars().collect();
                        editor.cursor = editor.text.len();
                        editor.history_index = None;
                        if command.argument.is_some() { continue; }
                        suggestions.dismiss();
                        menu.draw(&suggestions, prompt, &editor)?;
                    }
                    let input: String = editor.text.iter().collect();
                    // Empty input would echo blank prompts into the output area.
                    if input.trim().is_empty() { continue; }
                    menu.submit(prompt, &input)?;
                    if !input.trim().is_empty() && history.last() != Some(&input) {
                        history.push(input.clone());
                        if history.len() > 100 { history.remove(0); }
                    }
                    return Ok(Some(input));
                }
                code => {
                    editor.key(code, key.modifiers, history);
                    if !matches!(code, KeyCode::Up | KeyCode::Down) { editor.history_index = None; }
                }
            },
            Event::Paste(text) => editor.insert(&text),
            Event::Resize(_, _) => menu.follow_resize()?,
            _ => {}
        }
    }
}

pub struct SearchReport { pub results: Results, pub cancelled: bool }

// Live and finished results share row styling and a stable domain order.
pub async fn live<F>(checks: FuturesUnordered<F>, domains: Vec<String>, prices: tokio::sync::watch::Receiver<Catalog>, keyboard: bool) -> io::Result<(SearchReport, Panel)>
where F: std::future::Future<Output = (usize, (String, Availability))> {
    let _restore = Restore::enter()?;
    execute!(io::stdout(), cursor::Hide)?;
    write!(io::stdout(), "\r\n")?;
    io::stdout().flush()?;
    let mut panel = Panel::new(domains.clone())?;
    let mut frame = 0;
    let report = drive(checks, domains, prices, |rows, prices| {
        frame += 1;
        panel.rows.clone_from_slice(rows);
        if keyboard {
            while event::poll(Duration::ZERO)? {
                match event::read()? {
                    Event::Key(key) if key.kind != event::KeyEventKind::Release => match key.code {
                        KeyCode::Esc => return Ok(true),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
                        KeyCode::Down => panel.offset = (panel.offset + 1).min(panel.domains.len().saturating_sub(panel.visible)),
                        KeyCode::Up => panel.offset = panel.offset.saturating_sub(1),
                        KeyCode::PageDown => panel.offset = (panel.offset + panel.visible).min(panel.domains.len().saturating_sub(panel.visible)),
                        KeyCode::PageUp => panel.offset = panel.offset.saturating_sub(panel.visible),
                        KeyCode::Home => panel.offset = 0,
                        KeyCode::End => panel.offset = panel.domains.len().saturating_sub(panel.visible),
                        _ => {}
                    },
                    Event::Resize(_, _) => panel.reflow()?,
                    _ => {}
                }
            }
        }
        panel.paint(prices, frame)?;
        Ok(false)
    }).await?;
    Ok((report, panel))
}

// The same coordinator drives terminal rendering and deterministic headless tests.
// A true return from render cancels pending futures without waiting for pricing.
pub(crate) async fn drive<F>(mut checks: FuturesUnordered<F>, domains: Vec<String>, mut prices: tokio::sync::watch::Receiver<Catalog>, mut render: impl FnMut(&[Option<Availability>], &Catalog) -> io::Result<bool>) -> io::Result<SearchReport>
where F: std::future::Future<Output = (usize, (String, Availability))> {
    let mut rows: Vec<Option<Availability>> = vec![None; domains.len()];
    let mut updates = true;
    let mut cancelled = false;
    let mut tick = tokio::time::interval(Duration::from_millis(80));
    while !checks.is_empty() {
        tokio::select! {
            result = checks.next() => if let Some((i, (_, status))) = result { rows[i] = Some(status); },
            update = prices.changed(), if updates => { updates = update.is_ok(); }
            _ = tick.tick() => {}
        }
        let catalog = prices.borrow().clone();
        if render(&rows, &catalog)? { cancelled = true; break; }
    }
    Ok(SearchReport { results: domains.into_iter().zip(rows).map(|(d, s)| (d, s.unwrap_or(Availability::Unknown(UnknownReason::Cancelled)))).collect(), cancelled })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(text: &str) -> String {
        let mut escape = false;
        text.chars().filter(|c| {
            if *c == '\u{1b}' { escape = true; return false; }
            if escape { if *c == 'm' { escape = false; } return false; }
            true
        }).collect()
    }

    #[test]
    fn rows_fit_narrow_terminals_and_secondary_dates_stay_in_details() {
        let prices = crate::pricing::fixture_catalog(false);
        let dates = crate::model::DomainDates { registered: Some("2020-01-01".into()), updated: Some("2026-01-01".into()), expires: Some("2027-03-11".into()) };
        for status in [Availability::Available, Availability::Taken(dates.clone()), Availability::Unknown(UnknownReason::Inconclusive), Availability::Protected(ProtectionReason::Reserved)] {
            for width in 0..120 {
                let line = plain(&row("example.com", Some(&status), 18, &prices, width, 0));
                assert!(line.chars().count() <= width, "width {width}: {line}");
                if line.contains("reg 2") { assert!(line.contains("reg 2020-01-01")); }
            }
        }
        let line = plain(&row("example.com", Some(&Availability::Taken(dates.clone())), 11, &prices, 80, 0));
        assert!(line.chars().skip(RESULT_NAME_COL).collect::<String>().starts_with("example.com"), "{line:?}");
        assert!(line.contains("reg 2020-01-01  upd 2026-01-01  exp 2027-03-11"), "{line:?}");
        // Narrow rows keep the expiry before registration history.
        let narrow = plain(&row("example.com", Some(&Availability::Taken(dates.clone())), 11, &prices, 34, 0));
        assert!(narrow.ends_with("exp 2027-03-11") && !narrow.contains("reg"), "{narrow:?}");
        let detail = details("example.com", &Availability::Taken(dates), &prices).join("\n");
        assert!(detail.contains("Registered: 2020-01-01") && detail.contains("Updated: 2026-01-01"));
        let missing = vec![("example.gg".into(), Availability::Available), ("example.io".into(), Availability::Available)];
        assert_eq!(price_notice(&missing, &prices), Some("Some price estimates are unavailable."));
        assert_eq!(price_notice(&missing, &crate::pricing::fixture_catalog(true)), Some("fetching prices…"));
        assert!(!row("example.gg", Some(&Availability::Available), 11, &prices, 80, 0).contains("unavailable"));
    }

    #[test]
    fn inconclusive_rows_show_reasons_and_retry_counts_without_wrapping() {
        let prices = crate::pricing::fixture_catalog(false);
        for reason in [UnknownReason::Timeout, UnknownReason::RateLimited, UnknownReason::InvalidResponse,
            UnknownReason::Unreachable, UnknownReason::ServiceUnavailable, UnknownReason::NoRegistryService,
            UnknownReason::Cancelled, UnknownReason::NotChecked] {
            let status = Availability::Unknown(reason);
            assert!(plain(&row("example.gg", Some(&status), 10, &prices, 80, 0)).contains(reason.label()));
            assert!(details("example.gg", &status, &prices).iter().any(|line| line.contains(reason.label())));
            for width in 0..80 {
                assert!(plain(&row("example.gg", Some(&status), 10, &prices, width, 0)).chars().count() <= width);
            }
        }
        let mut results = vec![("example.com".into(), Availability::Available)];
        assert_eq!(retry_hint(&results), None);
        results.push(("example.gg".into(), Availability::Unknown(UnknownReason::RateLimited)));
        assert_eq!(retry_hint(&results).unwrap(), "/retry to check that domain again");
        results.push(("example.io".into(), Availability::Unknown(UnknownReason::Timeout)));
        assert_eq!(retry_hint(&results).unwrap(), "/retry to check those 2 again");
    }

    #[test]
    fn rows_show_porkbun_price_and_details_keep_full_renewal_quotes() {
        let prices = crate::pricing::fixture_catalog(false);
        let status = Availability::Available;
        let line = plain(&row("example.com", Some(&status), 11, &prices, 80, 0));
        assert!(line.contains("$11.08 on Porkbun"));
        assert!(!line.contains("renewal") && !line.contains("$12.00"));
        assert!(details("example.com", &status, &prices).iter()
            .any(|line| line == "Estimate: $11.08 first year · $12.00/yr renewal on Porkbun"));
        for width in 0..100 {
            let line = plain(&row("example.com", Some(&status), 11, &prices, width, 0));
            assert!(line.chars().count() <= width);
            if line.contains("$11.08") { assert!(line.contains("on Porkbun")); }
        }
    }

    #[test]
    fn cursor_offsets_ignore_prompt_color_sequences() {
        assert_eq!(prompt_width("  ❯❯❯ "), 6);
        assert_eq!(prompt_width("  \x1b[1;38;2;255;60;90m❯\x1b[0m❯❯ "), 6);
        assert_eq!(prompt_width(&crate::input_prompt()), 6);
    }

    #[test]
    fn composer_fits_small_terminals_and_preserves_editing_positions() {
        let mut editor = Editor::default();
        editor.insert("phagy");
        editor.key(KeyCode::Left, KeyModifiers::NONE, &[]);
        let mut suggestions = crate::commands::Suggestions::default();
        for input in ["", "/", "/wa"] {
            suggestions.update(input);
            for columns in [1, 2, 4, 10, 21, 28, 80, 120, 200] {
                for height in [1, 2, 4, 6, 24, 40] {
                    let frame = composer_frame(&suggestions, &crate::input_prompt(), &editor, columns, height);
                    assert!(frame.lines.len() <= height as usize);
                    assert!(frame.cursor.0 < columns as usize);
                    assert!(frame.cursor.1 < frame.lines.len());
                    for line in frame.lines {
                        assert!(prompt_width(&line) <= columns.saturating_sub(1) as usize, "{columns} columns: {line}");
                    }
                }
            }
        }
        // Like the classic CLI: just the prompt line, no box or footer.
        let frame = composer_frame(&Default::default(), "  > ", &editor, 80, 24);
        assert_eq!(frame.cursor, (8, 0));
        assert_eq!(frame.lines.iter().map(|line| plain(line)).collect::<Vec<_>>(), ["  > phagy"]);
        // The command menu opens above the prompt, which stays on the last row.
        suggestions.update("/");
        let frame = composer_frame(&suggestions, "  > ", &Editor::default(), 80, 24);
        assert!(frame.lines.len() > 2 && plain(&frame.lines[0]).contains("/tlds"));
        assert_eq!(frame.cursor.1, frame.lines.len() - 1);
        assert_eq!(plain(frame.lines.last().unwrap()), "  > ");
    }

    #[test]
    fn resized_prompt_is_found_with_and_without_reflow() {
        // Menu (two rows) above the prompt, drawn at 90 columns.
        let cells = [70, 52, 12];
        assert_eq!(composer_top(&cells, (8, 2), 90, 24, 23), 21, "unchanged");
        assert_eq!(composer_top(&cells, (8, 2), 90, 30, 23), 21, "taller, blank rows below");
        // Narrowed to 60: the 70-cell row wraps into two, bottom stays anchored.
        assert_eq!(composer_top(&cells, (8, 2), 60, 24, 23), 20);
        // Taller without reflow: blank rows appear below, nothing above is cleared.
        assert_eq!(composer_top(&cells, (8, 2), 60, 30, 23), 21);
    }

    #[test]
    fn banner_is_the_left_aligned_classic_logo() {
        let lines: Vec<_> = banner().iter().map(|line| plain(line)).collect();
        assert!(lines.iter().any(|line| line.starts_with("  |____/") && line.ends_with(concat!("v", env!("CARGO_PKG_VERSION")))));
        assert!(lines.iter().any(|line| line == "  type a name and hit enter. /help for commands · esc to quit."));
    }

    #[test]
    fn composer_context_and_live_progress_fit_the_viewport() {
        let prices = crate::pricing::fixture_catalog(false);
        let domains: Vec<_> = (0..32).map(|i| format!("example{i}.com")).collect();
        let mut rows = vec![None; domains.len()];
        rows[0] = Some(Availability::Available);
        rows[1] = Some(Availability::Unknown(UnknownReason::Timeout));
        for columns in [1, 2, 10, 28, 52, 68, 80, 120, 200] {
            for height in [1, 2, 4, 6, 24] {
                let width = content_width(columns);
                let visible = domains.len().min((height as usize).saturating_sub(2).max(1));
                for offset in [0, domains.len() - visible] {
                    let lines = search_lines(&domains, &rows, &prices, offset, visible, width, height, 0);
                    assert!(lines.len() <= height);
                    assert!(lines.iter().all(|line| prompt_width(line) <= width));
                }
            }
        }
        let lines = search_lines(&domains, &rows, &prices, 28, 4, 80, 7, 0);
        assert!(plain(&lines[0]).contains("example28.com"));
        assert!(plain(lines.last().unwrap()).contains("29–32/32"));
    }

    #[test]
    fn word_delete_and_kill_to_end_preserve_text_around_the_cursor() {
        let mut editor = Editor::default();
        editor.insert("/watch example.com later");
        editor.cursor = 18;
        editor.key(KeyCode::Char('w'), KeyModifiers::CONTROL, &[]);
        assert_eq!(editor.text.iter().collect::<String>(), "/watch  later");
        assert_eq!(editor.cursor, 7);
        editor.key(KeyCode::Char('k'), KeyModifiers::CONTROL, &[]);
        assert_eq!(editor.text.iter().collect::<String>(), "/watch ");
        editor.key(KeyCode::Char('w'), KeyModifiers::CONTROL, &[]);
        assert!(editor.text.is_empty());
        editor.key(KeyCode::Char('w'), KeyModifiers::CONTROL, &[]);
        assert_eq!(editor.cursor, 0);
    }

    #[test]
    fn short_me_names_show_possible_premium_without_a_catalog_quote() {
        let prices = crate::pricing::fixture_catalog(false);
        let status = Availability::Available;
        let rendered = plain(&row("go.me", Some(&status), 5, &prices, 80, 0));
        assert!(rendered.contains("⚠ likely premium"));
        assert!(details("go.me", &status, &prices).iter().any(|line| line.contains("Possibly premium")));
        assert!(!plain(&row("project.me", Some(&status), 10, &prices, 80, 0)).contains("premium"));
        assert!(!plain(&row("go.me", Some(&Availability::Taken(Default::default())), 5, &prices, 80, 0)).contains("premium"));
        // Keep the warning on compact rows even without a catalog price.
        let compact = plain(&row("go.ai", Some(&status), 5, &prices, 40, 0));
        assert!(compact.contains("⚠ likely premium"));
    }

    #[test]
    fn trademark_protection_is_separate_from_registration_and_failed_checks() {
        let prices = crate::pricing::fixture_catalog(false);
        let protected = Availability::Protected(ProtectionReason::Trademark);
        let rendered = plain(&row("apple.fyi", Some(&protected), 14, &prices, 80, 0));
        assert!(rendered.contains("★") && rendered.contains("trademark protected"));
        assert!(!rendered.contains('$') && !rendered.contains('?'));
        assert_eq!(protected.as_str(), "protected");
        assert!(details("apple.fyi", &protected, &prices).iter().any(|line| line.contains("DPML")));
        assert!(retry_hint(&vec![("apple.fyi".into(), protected)]).is_none());
    }

    #[tokio::test]
    async fn cancelling_drops_pending_checks_and_returns_inconclusive() {
        struct Dropped(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped { fn drop(&mut self) { self.0.store(true, std::sync::atomic::Ordering::SeqCst); } }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let checks = [async move {
            let _guard = guard;
            std::future::pending::<(usize, (String, Availability))>().await
        }].into_iter().collect();
        let (_sender, prices) = tokio::sync::watch::channel(crate::pricing::fixture_catalog(true));
        let report = tokio::time::timeout(Duration::from_secs(1), drive(checks, vec!["example.com".into()], prices, |_, _| Ok(true))).await.unwrap().unwrap();
        assert!(report.cancelled);
        assert_eq!(report.results[0].1.as_str(), "unknown");
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    // Invoked only by Tools/test_ui.py in a PTY with temporary HOME.
    // No registries, scheduler, notifier, or real OS settings are used.
    #[tokio::test]
    #[ignore = "Deterministic PTY fixture, run by Tools/test_ui.py"]
    async fn terminal_fixture() {
        assert_eq!(std::env::var("DOTT_UI_FIXTURE").as_deref(), Ok("1"));
        let _session = Session::enter().unwrap();
        crate::print_cat();
        let (_sender, prices) = tokio::sync::watch::channel(crate::pricing::fixture_catalog(false));
        let mut history = Vec::new();
        let mut results = vec![
            ("example.com".into(), Availability::Available),
            ("example.io".into(), Availability::Taken(crate::model::DomainDates { registered: Some("2020-01-01".into()), updated: Some("2026-01-01".into()), expires: Some("2027-03-11".into()) })),
            ("example.gg".into(), Availability::Unknown(UnknownReason::RateLimited)),
            ("example.dev".into(), Availability::Protected(ProtectionReason::Reserved)),
        ];
        loop {
            println!("FIXTURE_READY");
            let Some(input) = read_input(&plain(&crate::input_prompt()), &mut history).unwrap() else { break; };
            if input == "quit" { break; }
            if input == "cancel" || input == "browse" {
                let domains = if input == "browse" { (0..32).map(|i| format!("example{i}.com")).collect() }
                    else { vec!["example.com".into()] };
                let checks = domains.iter().map(|_| std::future::pending()).collect();
                let (report, mut shown) = live(checks, domains, prices.clone(), true).await.unwrap();
                assert!(report.cancelled);
                shown.finish(&report.results, &prices.borrow(), Vec::new(), true).unwrap();
                println!("CANCELLED");
            } else if input == "show" || input == "taken" {
                if input == "taken" { results[0].1 = Availability::Taken(crate::model::DomainDates::default()); }
                let checks = results.clone().into_iter().enumerate().map(|(i, result)| std::future::ready((i, result))).collect();
                let (report, mut shown) = live(checks, results.iter().map(|(d, _)| d.clone()).collect(), prices.clone(), true).await.unwrap();
                let changes = crate::history::record(&report.results).unwrap();
                shown.finish(&report.results, &prices.borrow(), changes, false).unwrap();
            } else if input == "/tlds" {
                let chosen = crate::extensions::select(&["com", "io"]).unwrap();
                println!("ACTION:Tlds({chosen:?})");
            } else if input == "/results" {
                print_results(&results, &prices.borrow(), &[], false).unwrap();
            } else if input.starts_with("/watch ") { println!("ACTION:Watch({:?})", input.trim_start_matches("/watch ")); }
            else if input.ends_with('+') { println!("ACTION:Related({:?})", input.trim_end_matches('+')); }
            else if input == "/retry" {
                println!("ACTION:Retry");
                assert_eq!(crate::retry_domains(&results), vec![("example".into(), "gg")]);
                crate::merge_retry(&mut results, vec![("example.gg".into(), Availability::Available)]);
            } else { println!("INPUT:{input}"); }
        }
        println!("FIXTURE_DONE");
    }
    #[test]
    fn editor_edits_at_cursor_and_restores_draft_after_history() {
        let mut editor = Editor::default();
        let history = vec!["first".into(), "second".into()];
        editor.insert("ac");
        editor.key(KeyCode::Left, KeyModifiers::NONE, &history);
        editor.insert("b");
        assert_eq!(editor.text.iter().collect::<String>(), "abc");
        editor.key(KeyCode::Delete, KeyModifiers::NONE, &history);
        assert_eq!(editor.text.iter().collect::<String>(), "ab");
        editor.key(KeyCode::Up, KeyModifiers::NONE, &history);
        editor.key(KeyCode::Up, KeyModifiers::NONE, &history);
        assert_eq!(editor.text.iter().collect::<String>(), "first");
        editor.key(KeyCode::Down, KeyModifiers::NONE, &history);
        editor.key(KeyCode::Down, KeyModifiers::NONE, &history);
        assert_eq!(editor.text.iter().collect::<String>(), "ab");
        editor.key(KeyCode::Char('u'), KeyModifiers::CONTROL, &history);
        assert!(editor.text.is_empty());
    }
    #[test]
    fn paste_is_one_bounded_editable_line_and_long_inputs_scroll() {
        let mut editor = Editor::default();
        editor.insert("name\n/watch example.com\u{1b}");
        assert_eq!(editor.text.iter().collect::<String>(), "name /watch example.com");
        let (text, cursor) = editor.visible(8);
        assert!(text.len() <= 8 && cursor < 8);
        editor.insert(&"x".repeat(5000));
        assert_eq!(editor.text.len(), 4096);
    }
}
