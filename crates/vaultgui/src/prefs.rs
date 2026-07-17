//! Non-secret UI preferences, persisted as a tiny `key=value` file. NO secret
//! material is ever written here (only the idle timeout, theme, and last vault
//! path). Hand-rolled parser: zero new dependencies (supply-chain posture).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    System,
    Light,
    Dark,
}

impl Theme {
    fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
    fn parse(s: &str) -> Theme {
        match s {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::System,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefs {
    /// `None` = auto-lock idle timer disabled; `Some(secs)` otherwise.
    pub idle_timeout_secs: Option<u64>,
    pub theme: Theme,
    pub last_vault_path: Option<String>,
    /// Opt-in gate on the REVEAL action (see `hello.rs`). Never contributes to
    /// the KEK/passphrase factor -- defaults to `false` (off).
    pub hello_enabled: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            idle_timeout_secs: Some(300),
            theme: Theme::System,
            last_vault_path: None,
            hello_enabled: false,
        }
    }
}

impl Prefs {
    pub fn to_serialized(&self) -> String {
        let mut s = String::new();
        match self.idle_timeout_secs {
            Some(n) => s.push_str(&format!("idle_timeout_secs={n}\n")),
            None => s.push_str("idle_timeout_secs=off\n"),
        }
        s.push_str(&format!("theme={}\n", self.theme.as_str()));
        if let Some(p) = &self.last_vault_path {
            s.push_str(&format!("last_vault_path={p}\n"));
        }
        s.push_str(&format!("hello_enabled={}\n", if self.hello_enabled { "true" } else { "false" }));
        s
    }

    pub fn from_serialized(text: &str) -> Prefs {
        let mut p = Prefs::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "idle_timeout_secs" => {
                    p.idle_timeout_secs = match v.trim() {
                        "off" => None,
                        other => other.parse::<u64>().ok().or(p.idle_timeout_secs),
                    };
                }
                "theme" => p.theme = Theme::parse(v.trim()),
                "last_vault_path" => p.last_vault_path = Some(v.trim().to_string()),
                "hello_enabled" => {
                    p.hello_enabled = match v.trim() {
                        "true" => true,
                        "false" => false,
                        _ => p.hello_enabled,
                    };
                }
                _ => {}
            }
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_all_fields() {
        let p = Prefs {
            idle_timeout_secs: Some(120),
            theme: Theme::Dark,
            last_vault_path: Some("C:\\vaults\\my.ztsv".into()),
            hello_enabled: true,
        };
        let back = Prefs::from_serialized(&p.to_serialized());
        assert_eq!(back, p);
    }

    #[test]
    fn hello_enabled_roundtrips_and_defaults_false() {
        assert_eq!(Prefs::default().hello_enabled, false);

        let p = Prefs { hello_enabled: true, ..Prefs::default() };
        let back = Prefs::from_serialized(&p.to_serialized());
        assert_eq!(back.hello_enabled, true);

        // Absent key (e.g. prefs written before this field existed) leniently
        // defaults to false rather than failing to parse.
        let back = Prefs::from_serialized("theme=light\n");
        assert_eq!(back.hello_enabled, false);
    }

    #[test]
    fn timeout_off_roundtrips_to_none() {
        let p = Prefs { idle_timeout_secs: None, ..Prefs::default() };
        let back = Prefs::from_serialized(&p.to_serialized());
        assert_eq!(back.idle_timeout_secs, None);
    }

    #[test]
    fn unknown_keys_and_blank_lines_are_ignored() {
        let back = Prefs::from_serialized("# comment\n\nfuture_key=whatever\ntheme=light\n");
        assert_eq!(back.theme, Theme::Light);
        assert_eq!(back, Prefs { theme: Theme::Light, ..Prefs::default() });
    }

    #[test]
    fn default_is_5min_system_theme() {
        assert_eq!(Prefs::default().idle_timeout_secs, Some(300));
        assert_eq!(Prefs::default().theme, Theme::System);
    }
}
