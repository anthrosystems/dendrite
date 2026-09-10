//! Command-line parsing foundation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Status,
    Incidents,
    Memory,
    Actions,
    Health,
    Version,
    Help,
}

impl Command {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("status") => Self::Status,
            Some("incidents") => Self::Incidents,
            Some("memory") => Self::Memory,
            Some("actions") => Self::Actions,
            Some("health") => Self::Health,
            Some("version") | Some("--version") | Some("-V") => Self::Version,
            _ => Self::Help,
        }
    }
}

pub fn render(command: Command) -> String {
    match command {
        Command::Status => "Dendrite status: daemon IPC not connected yet".into(),
        Command::Incidents => "Incident IPC command scaffolded".into(),
        Command::Memory => "Memory IPC command scaffolded".into(),
        Command::Actions => "Action IPC command scaffolded".into(),
        Command::Health => "Guard health IPC command scaffolded".into(),
        Command::Version => format!("dendrite {}", env!("CARGO_PKG_VERSION")),
        Command::Help => {
            "Usage: dendrite <status|incidents|memory|actions|health|version>".into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_command() {
        assert_eq!(Command::parse(Some("memory")), Command::Memory);
    }

    #[test]
    fn unknown_command_falls_back_to_help() {
        assert_eq!(Command::parse(Some("nope")), Command::Help);
    }
}
