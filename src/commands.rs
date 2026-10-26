#[derive(Clone, Copy)]
pub struct Command {
    pub name: &'static str,
    pub argument: Option<&'static str>,
    pub description: &'static str,
}

impl Command {
    pub fn usage(&self) -> String {
        match self.argument {
            Some(argument) => format!("{} {argument}", self.name),
            None => self.name.into(),
        }
    }

    pub fn completion(&self) -> String {
        format!("{}{}", self.name, if self.argument.is_some() { " " } else { "" })
    }
}

// Shared by the slash menu and /help, so every advertised command stays in sync.
pub const COMMANDS: &[Command] = &[
    Command { name: "/tlds", argument: None, description: "Choose extensions" },
    Command { name: "/watch", argument: Some("<domain>"), description: "Watch a domain" },
    Command { name: "/list", argument: None, description: "Show watchlist" },
    Command { name: "/results", argument: None, description: "Show last results" },
    Command { name: "/retry", argument: None, description: "Retry inconclusive checks" },
    Command { name: "/details", argument: Some("<domain>"), description: "Inspect a result" },
    Command { name: "/shortlist", argument: None, description: "List saved names" },
    Command { name: "/save", argument: Some("<domain>"), description: "Save a name" },
    Command { name: "/unsave", argument: Some("<domain>"), description: "Remove a saved name" },
    Command { name: "/unwatch", argument: Some("<domain>"), description: "Stop watching" },
    Command { name: "/update", argument: None, description: "Update dott" },
    Command { name: "/help", argument: None, description: "Show help" },
];

#[derive(Default)]
pub struct Suggestions {
    input: String,
    options: Vec<&'static Command>,
    selected: usize,
    dismissed: bool,
}

impl Suggestions {
    pub fn update(&mut self, input: &str) {
        if self.input == input { return; }
        self.input = input.into();
        self.selected = 0;
        self.dismissed = false;
        let prefix = input.trim_start().to_ascii_lowercase();
        self.options = if prefix.starts_with('/') && !prefix.chars().any(char::is_whitespace) {
            COMMANDS.iter().filter(|command| command.name.starts_with(&prefix)).collect()
        } else { Vec::new() };
    }

    pub fn options(&self) -> &[&'static Command] {
        if self.dismissed { &[] } else { &self.options }
    }

    pub fn selected_index(&self) -> usize { self.selected }

    pub fn current(&self) -> Option<&'static Command> { self.options().get(self.selected).copied() }

    pub fn move_by(&mut self, delta: isize) {
        let count = self.options().len();
        if count > 0 { self.selected = (self.selected as isize + delta).rem_euclid(count as isize) as usize; }
    }

    pub fn dismiss(&mut self) { self.dismissed = true; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_suggestions_filter_and_leave_arguments_and_names_alone() {
        let mut suggestions = Suggestions::default();
        suggestions.update("/");
        assert_eq!(suggestions.options().len(), COMMANDS.len());
        suggestions.update("/WA");
        assert_eq!(suggestions.current().unwrap().name, "/watch");
        for input in ["name", "name.si", "/watch example.si", "/watch ", "/nonexistent"] {
            suggestions.update(input);
            assert!(suggestions.options().is_empty(), "{input}");
        }
    }

    #[test]
    fn arrows_wrap_and_escape_dismissal_lasts_until_input_changes() {
        let mut suggestions = Suggestions::default();
        suggestions.update("/re");
        assert_eq!(suggestions.current().unwrap().name, "/results");
        suggestions.move_by(1);
        assert_eq!(suggestions.current().unwrap().name, "/retry");
        suggestions.move_by(1);
        assert_eq!(suggestions.current().unwrap().name, "/results");
        suggestions.move_by(-1);
        assert_eq!(suggestions.current().unwrap().name, "/retry");
        suggestions.dismiss();
        suggestions.update("/re");
        assert!(suggestions.options().is_empty());
        suggestions.update("/ret");
        assert_eq!(suggestions.current().unwrap().name, "/retry");
    }

    #[test]
    fn command_arguments_are_prefilled_without_submitting_them() {
        let watch = COMMANDS.iter().find(|command| command.name == "/watch").unwrap();
        assert_eq!(watch.usage(), "/watch <domain>");
        assert_eq!(watch.completion(), "/watch ");
        let help = COMMANDS.iter().find(|command| command.name == "/help").unwrap();
        assert_eq!(help.completion(), "/help");
        assert!(help.argument.is_none());
    }
}
