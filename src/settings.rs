//! Preferences shared by the dashboard, the background service and the CLI.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Settings {
    /// Scan automatically this often while the dashboard (or background
    /// service) is running. 0 turns it off.
    pub auto_scan_minutes: u32,
    /// Desktop notifications for new devices and security issues found by
    /// automatic scans.
    pub notifications: bool,
    /// Phone alerts for the same events (contains tokens, so the file is
    /// readable only by its owner).
    pub alerts: Vec<crate::alerts::AlertTarget>,
    /// Let devices on the local network open the dashboard with `phone_key`.
    pub phone_access: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_key: Option<String>,
}

impl Settings {
    fn path(root: &Path) -> std::path::PathBuf {
        root.join("settings.json")
    }

    pub fn path_in(root: &Path) -> std::path::PathBuf {
        Self::path(root)
    }

    pub fn load(root: &Path) -> Settings {
        std::fs::read_to_string(Self::path(root)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        std::fs::create_dir_all(root).with_context(|| format!("couldn't create {}", root.display()))?;
        let path = Self::path(root);
        let tmp = path.with_extension("json.tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        // Created private from the start: it can hold alert tokens.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        std::io::Write::write_all(&mut opts.open(&tmp)?, &serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_defaults() {
        let dir = std::env::temp_dir().join(format!("nattowok-settings-{}", std::process::id()));
        assert_eq!(Settings::load(&dir), Settings::default());
        let s = Settings { auto_scan_minutes: 15, notifications: true, ..Default::default() };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("settings.json")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
