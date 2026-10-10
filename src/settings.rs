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
}

impl Settings {
    fn path(root: &Path) -> std::path::PathBuf {
        root.join("settings.json")
    }

    pub fn load(root: &Path) -> Settings {
        std::fs::read_to_string(Self::path(root)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        std::fs::create_dir_all(root).with_context(|| format!("couldn't create {}", root.display()))?;
        std::fs::write(Self::path(root), serde_json::to_vec_pretty(self)?)?;
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
        let s = Settings { auto_scan_minutes: 15, notifications: true };
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
