use colored::*;
use crossterm::{
    cursor, event::{self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyModifiers},
    execute, queue,
    terminal::{self, Clear, ClearType, DisableLineWrap, EnableLineWrap},
};
use futures::{stream::FuturesUnordered, StreamExt};
use std::{io::{self, Write}, time::Duration};
use crate::{model::{Availability, UnknownReason, ProtectionReason}, pricing::Catalog};

pub type Results = Vec<(String, Availability)>;

pub fn width() -> usize { terminal::size().map(|(w, _)| w as usize).unwrap_or(80) }

// All result data is validated ASCII. UI symbols occupy one terminal cell.
pub fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width { return text.into(); }
    if width == 0 { return String::new(); }
    text.chars().take(width - 1).chain(std::iter::once('…')).collect()
}

fn month_date(date: &str) -> Option<String> {
    let date = crate::utils::parse_date(date)?;
    let month: usize = date[5..7].parse().ok()?;
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    Some(format!("{} {}", months[month - 1], &date[..4]))
}

pub fn row(domain: &str, status: Option<&Availability>, pad: usize, prices: &Catalog, width: usize, frame: usize) -> String {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let symbol = match status {
        Some(Availability::Available) => "✓".truecolor(32, 215, 96),
        Some(Availability::Taken(_)) => "✗".truecolor(145, 145, 155),
        Some(Availability::Protected(_)) => "★".truecolor(205, 170, 105),
        Some(Availability::Unknown(_)) => "?".bright_yellow(),
        None => FRAMES[frame % FRAMES.len()].truecolor(180, 130, 230),
    };
    let prefix = "  ";
    let budget = width.saturating_sub(6);
    if width < 6 { return clip(domain, width); }
    let name = clip(domain, budget);
    let padded = format!("{name:<pad$}", pad = pad.min(budget).max(name.chars().count()));
    let spare = budget.saturating_sub(padded.chars().count());
    let metadata = match status {
        Some(Availability::Available) => {
            let premium = crate::config::is_likely_premium(domain);
            match prices.first_year_quote(domain) {
                Some(quote) if premium => {
                    let full = format!("  {quote} · possibly premium");
                    if full.chars().count() <= spare { full } else { "  possibly premium".into() }
                }
                Some(quote) => format!("  {quote}"),
                None if premium => "  possibly premium".into(),
                None => String::new(),
            }
        }
        Some(Availability::Taken(dates)) => dates.expires.as_deref().and_then(month_date)
            .map(|date| format!("  expires {date}")).unwrap_or_default(),
        Some(Availability::Protected(reason)) => format!("  {}", reason.label()),
        Some(Availability::Unknown(reason)) => format!("  {}", reason.label()),
        _ => String::new(),
    };
    // Omit secondary details rather than displaying a partial price or date.
    let metadata = if metadata.chars().count() <= spare { metadata } else { String::new() };
    let styled_name = if matches!(status, Some(Availability::Available)) {
        padded.truecolor(32, 215, 96).bold()
    } else { padded.truecolor(155, 155, 165) };
    let styled_metadata = if matches!(status, Some(Availability::Available)) {
        metadata.truecolor(228, 76, 225)
    } else { metadata.truecolor(150, 165, 175) };
    format!("{prefix}{symbol}  {styled_name}{styled_metadata}")
}

pub fn summary(results: &Results) -> String {
    let mut counts = [0; 4];
    for (_, status) in results {
        counts[match status { Availability::Available => 0, Availability::Taken(_) => 1, Availability::Protected(_) => 2, Availability::Unknown(_) => 3 }] += 1;
    }
    let mut parts = vec![format!("{} available", counts[0]), format!("{} taken", counts[1])];
    if counts[2] > 0 {
        let label = if results.iter().any(|(_, status)| matches!(status, Availability::Protected(ProtectionReason::Trademark))) { "protected" } else { "reserved" };
        parts.push(format!("{} {label}", counts[2]));
    }
    if counts[3] > 0 { parts.push(format!("{} inconclusive", counts[3])); }
    parts.join(" · ")
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

// Live checks use a small inline area. Finished output is ordinary terminal
// text, so native selection and scrollback work without any interaction mode.
pub struct Panel {
    domains: Vec<String>,
    rows: Vec<Option<Availability>>,
    origin: u16,
    size: (u16, u16),
    offset: usize,
    visible: usize,
}

impl Panel {
    fn new(domains: Vec<String>) -> io::Result<Self> {
        let size = terminal::size()?;
        let origin = cursor::position()?.1;
        let mut panel = Self { rows: vec![None; domains.len()], domains, origin, size, offset: 0, visible: 0 };
        panel.reflow()?;
        Ok(panel)
    }

    fn reflow(&mut self) -> io::Result<()> {
        self.size = terminal::size()?;
        self.visible = self.domains.len().min((self.size.1 as usize).saturating_sub(4).max(1));
        self.offset = self.offset.min(self.domains.len().saturating_sub(self.visible));
        self.origin = self.origin.min(self.size.1.saturating_sub(1));
        let reserved = (self.visible + 2).min(self.size.1.saturating_sub(1) as usize);
        let overflow = (self.origin as usize + reserved + 1).saturating_sub(self.size.1 as usize);
        if overflow > 0 {
            let mut out = io::stdout();
            queue!(out, cursor::MoveTo(0, self.size.1.saturating_sub(1)))?;
            for _ in 0..overflow { write!(out, "\r\n")?; }
            out.flush()?;
            self.origin = self.origin.saturating_sub(overflow as u16);
        }
        Ok(())
    }

    pub fn finish(&mut self, results: &Results, prices: &Catalog, changes: Vec<String>, cancelled: bool) -> io::Result<()> {
        execute!(io::stdout(), cursor::MoveTo(0, self.origin))?;
        print_results(results, prices, &changes, cancelled)
    }

    fn paint(&mut self, prices: &Catalog, frame: usize) -> io::Result<()> {
        if terminal::size()? != self.size { self.reflow()?; }
        let width = (self.size.0 as usize).saturating_sub(1);
        let pad = self.domains.iter().map(String::len).max().unwrap_or(0);
        let mut lines = Vec::new();
        for i in self.offset..(self.offset + self.visible).min(self.domains.len()) {
            lines.push(row(&self.domains[i], self.rows[i].as_ref(), pad, prices, width, frame));
        }
        let complete: Results = self.domains.iter().zip(&self.rows).filter_map(|(d, s)| s.as_ref().map(|s| (d.clone(), s.clone()))).collect();
        let status = format!("{} / {} checked · {}", complete.len(), self.domains.len(), summary(&complete));
        lines.push(clip(&format!("  {status}"), width).truecolor(175, 175, 185).to_string());
        let notice = if self.visible < self.domains.len() { "↑/↓ more rows · esc cancel" }
            else { price_notice(&complete, prices).unwrap_or("esc cancel") };
        lines.push(clip(&format!("  {notice}"), width).truecolor(150, 165, 175).to_string());
        let mut out = io::stdout();
        for (y, line) in lines.iter().enumerate().take(self.size.1.saturating_sub(1) as usize) {
            queue!(out, cursor::MoveTo(0, self.origin + y as u16), Clear(ClearType::CurrentLine))?;
            write!(out, "{line}")?;
        }
        out.flush()
    }
}

pub fn print_results(results: &Results, prices: &Catalog, changes: &[String], cancelled: bool) -> io::Result<()> {
    let width = width().saturating_sub(1);
    let pad = results.iter().map(|(d, _)| d.len()).max().unwrap_or(0);
    let mut lines: Vec<_> = results.iter().map(|(domain, status)| row(domain, Some(status), pad, prices, width, 0)).collect();
    lines.push(clip(&format!("  {}", summary(results)), width).truecolor(175, 175, 185).to_string());
    for domain in changes { lines.push(clip(&format!("  {domain} · taken since your last check"), width).truecolor(220, 150, 120).to_string()); }
    let notice = if cancelled { "Cancelled · unfinished checks are inconclusive" }
        else { price_notice(results, prices).unwrap_or("Porkbun estimates · /details <domain> for full dates") };
    lines.push(clip(&format!("  {notice}"), width).truecolor(150, 165, 175).to_string());
    if let Some(hint) = retry_hint(results) {
        lines.push(clip(&format!("  {hint}"), width).truecolor(150, 150, 165).to_string());
    }
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

#[derive(Default)]
struct CommandMenuView {
    anchor: Option<u16>,
    shown: usize,
}

impl CommandMenuView {
    fn clear(&mut self) -> io::Result<()> {
        if self.shown == 0 { return Ok(()); }
        let Some(anchor) = self.anchor else { return Ok(()); };
        let height = terminal::size()?.1;
        let mut out = io::stdout();
        for i in 0..self.shown {
            let row = anchor as usize + i + 1;
            if row < height as usize { queue!(out, cursor::MoveTo(0, row as u16), Clear(ClearType::CurrentLine))?; }
        }
        queue!(out, cursor::MoveTo(0, anchor.min(height.saturating_sub(1))))?;
        self.shown = 0;
        out.flush()
    }

    fn draw(&mut self, suggestions: &crate::commands::Suggestions, prompt: &str, editor: &Editor) -> io::Result<()> {
        let (columns, height) = terminal::size()?;
        let width = (columns as usize).saturating_sub(1);
        let capacity = (height as usize).saturating_sub(2).min(6);
        let options = suggestions.options();
        let visible = options.len().min(capacity);
        let selected = suggestions.selected_index();
        let start = selected.saturating_sub(visible.saturating_sub(1)).min(options.len().saturating_sub(visible));
        let mut lines = Vec::new();
        for (index, command) in options.iter().enumerate().skip(start).take(visible) {
            let text = clip(&format!("  {} {:<18} {}", if index == selected { "›" } else { " " }, command.usage(), command.description), width);
            lines.push(if index == selected { text.bright_white().bold().to_string() } else { text.truecolor(155, 155, 175).to_string() });
        }
        if visible > 0 {
            let hint = if width >= 55 { format!("  ↑/↓ choose · enter select · esc close · {}–{}/{}", start + 1, start + visible, options.len()) }
                else { format!("  ↑/↓ · enter · esc  {}–{}/{}", start + 1, start + visible, options.len()) };
            lines.push(clip(&hint, width).truecolor(145, 145, 165).to_string());
        }
        if !lines.is_empty() && self.anchor.is_none() { self.anchor = Some(cursor::position()?.1); }
        let mut out = io::stdout();
        if let Some(anchor) = self.anchor.as_mut() {
            *anchor = (*anchor).min(height.saturating_sub(1));
            let overflow = (*anchor as usize + lines.len() + 1).saturating_sub(height as usize);
            if overflow > 0 {
                queue!(out, cursor::MoveTo(0, height.saturating_sub(1)))?;
                for _ in 0..overflow { write!(out, "\r\n")?; }
                *anchor = anchor.saturating_sub(overflow as u16);
            }
            for i in 0..self.shown.max(lines.len()) {
                let row = *anchor as usize + i + 1;
                if row >= height as usize { break; }
                queue!(out, cursor::MoveTo(0, row as u16), Clear(ClearType::CurrentLine))?;
                if let Some(line) = lines.get(i) { write!(out, "{line}")?; }
            }
            queue!(out, cursor::MoveTo(0, *anchor))?;
        }
        self.shown = lines.len();
        let prompt_cells = prompt_width(prompt);
        let (visible, cursor_col) = editor.visible((columns as usize).saturating_sub(prompt_cells + 1).max(1));
        queue!(out, cursor::MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        write!(out, "{prompt}{visible}")?;
        queue!(out, cursor::MoveToColumn((prompt_cells + cursor_col).min(columns.saturating_sub(1) as usize) as u16))?;
        out.flush()
    }
}

// Prompt colors are ANSI SGR sequences and occupy no terminal cells.
fn prompt_width(prompt: &str) -> usize {
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
        match event::read()? {
            Event::Key(key) if key.kind != event::KeyEventKind::Release => match key.code {
                KeyCode::Esc if !suggestions.options().is_empty() => suggestions.dismiss(),
                KeyCode::Esc => { menu.clear()?; print!("\r\n"); return Ok(None); }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { menu.clear()?; print!("\r\n"); return Ok(None); }
                KeyCode::Up if !suggestions.options().is_empty() => suggestions.move_by(-1),
                KeyCode::Down if !suggestions.options().is_empty() => suggestions.move_by(1),
                KeyCode::Tab => {} // No result navigation mode.
                KeyCode::Enter => {
                    if let Some(command) = suggestions.current() {
                        editor.text = command.completion().chars().collect();
                        editor.cursor = editor.text.len();
                        editor.history_index = None;
                        if command.argument.is_some() { continue; }
                        suggestions.dismiss();
                        menu.draw(&suggestions, prompt, &editor)?;
                    }
                    menu.clear()?;
                    print!("\r\n");
                    let input: String = editor.text.iter().collect();
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
            Event::Resize(_, _) if menu.anchor.is_some() => {
                menu.clear()?;
                menu.anchor = Some(cursor::position()?.1);
            }
            _ => {}
        }
    }
}

pub struct SearchReport { pub results: Results, pub cancelled: bool }

// Pending and finished results use the exact same inline panel.
pub async fn live<F>(checks: FuturesUnordered<F>, domains: Vec<String>, prices: tokio::sync::watch::Receiver<Catalog>, keyboard: bool) -> io::Result<(SearchReport, Panel)>
where F: std::future::Future<Output = (usize, (String, Availability))> {
    let _restore = Restore::enter()?;
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
                assert!(!line.contains("2020") && !line.contains("2026"));
            }
        }
        let line = plain(&row("example.com", Some(&Availability::Taken(dates.clone())), 11, &prices, 80, 0));
        assert!(line.contains("expires Mar 2027"));
        let detail = details("example.com", &Availability::Taken(dates), &prices).join("\n");
        assert!(detail.contains("Registered: 2020-01-01") && detail.contains("Updated: 2026-01-01"));
        let missing = vec![("example.gg".into(), Availability::Available), ("example.io".into(), Availability::Available)];
        assert_eq!(price_notice(&missing, &prices), Some("Some price estimates are unavailable."));
        assert_eq!(price_notice(&missing, &crate::pricing::fixture_catalog(true)), Some("fetching prices…"));
        assert!(!row("example.gg", Some(&Availability::Available), 11, &prices, 80, 0).contains("unavailable"));
        assert_eq!(summary(&vec![("a.com".into(), Availability::Available), ("b.com".into(), Availability::Unknown(UnknownReason::Inconclusive))]), "1 available · 0 taken · 1 inconclusive");
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
    fn rows_show_first_year_and_details_keep_full_renewal_quotes() {
        let prices = crate::pricing::fixture_catalog(false);
        let status = Availability::Available;
        let line = plain(&row("example.com", Some(&status), 11, &prices, 80, 0));
        assert!(line.contains("$11.08 first year"));
        assert!(!line.contains("renewal") && !line.contains("$12.00"));
        assert!(details("example.com", &status, &prices).iter()
            .any(|line| line == "Estimate: $11.08 first year · $12.00/yr renewal on Porkbun"));
        for width in 0..100 {
            let line = plain(&row("example.com", Some(&status), 11, &prices, width, 0));
            assert!(line.chars().count() <= width);
            if line.contains("$11.08") { assert!(line.contains("first year")); }
        }
    }

    #[test]
    fn cursor_offsets_ignore_prompt_color_sequences() {
        assert_eq!(prompt_width("  > "), 4);
        assert_eq!(prompt_width("  \x1b[1;38;2;255;60;90m>\x1b[0m "), 4);
        assert_eq!(prompt_width(&crate::input_prompt()), 4);
    }

    #[test]
    fn short_me_names_show_possible_premium_without_a_catalog_quote() {
        let prices = crate::pricing::fixture_catalog(false);
        let status = Availability::Available;
        let rendered = plain(&row("go.me", Some(&status), 5, &prices, 80, 0));
        assert!(rendered.contains("possibly premium"));
        assert!(details("go.me", &status, &prices).iter().any(|line| line.contains("Possibly premium")));
        assert!(!plain(&row("project.me", Some(&status), 10, &prices, 80, 0)).contains("premium"));
        assert!(!plain(&row("go.me", Some(&Availability::Taken(Default::default())), 5, &prices, 80, 0)).contains("premium"));
        // Keep the warning on compact rows even without a catalog price.
        let compact = plain(&row("go.ai", Some(&status), 5, &prices, 30, 0));
        assert!(compact.contains("possibly premium"));
    }

    #[test]
    fn trademark_protection_is_separate_from_registration_and_failed_checks() {
        let prices = crate::pricing::fixture_catalog(false);
        let protected = Availability::Protected(ProtectionReason::Trademark);
        let rendered = plain(&row("apple.fyi", Some(&protected), 14, &prices, 80, 0));
        assert!(rendered.contains("★") && rendered.contains("trademark protected"));
        assert!(!rendered.contains('$') && !rendered.contains('?'));
        assert_eq!(protected.as_str(), "protected");
        assert!(summary(&vec![("apple.fyi".into(), protected.clone())]).contains("1 protected"));
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
            if input == "cancel" {
                let checks = [std::future::pending()].into_iter().collect();
                let (report, mut shown) = live(checks, vec!["example.com".into()], prices.clone(), true).await.unwrap();
                assert!(report.cancelled);
                shown.finish(&report.results, &prices.borrow(), Vec::new(), true).unwrap();
                println!("CANCELLED");
            } else if input == "show" || input == "taken" {
                if input == "taken" { results[0].1 = Availability::Taken(crate::model::DomainDates::default()); }
                let checks = results.clone().into_iter().enumerate().map(|(i, result)| std::future::ready((i, result))).collect();
                let (report, mut shown) = live(checks, results.iter().map(|(d, _)| d.clone()).collect(), prices.clone(), true).await.unwrap();
                let changes = crate::history::record(&report.results).unwrap();
                shown.finish(&report.results, &prices.borrow(), changes, false).unwrap();
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
    #[test]
    fn date_labels_remain_compact_and_validated() {
        assert_eq!(month_date("2027-03-11"), Some("Mar 2027".into()));
        assert_eq!(month_date("bad"), None);
    }
}
