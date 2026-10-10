//! Installs NattoWok as a per-user background service, so the dashboard and
//! automatic scans keep running after you close the terminal, and start again
//! when you log in. No administrator rights needed.
//!
//! - Linux: a systemd user unit
//! - macOS: a LaunchAgent
//! - Windows: a Task Scheduler task that runs at log-on

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

pub const LABEL: &str = "com.nattowok.agent";
pub const TASK_NAME: &str = "NattoWok";

/// The command the service runs.
pub fn service_args(data_dir: &Path, interface: Option<&str>) -> Vec<String> {
    let mut args = vec!["--data-dir".to_string(), data_dir.display().to_string()];
    if let Some(i) = interface {
        args.extend(["--interface".to_string(), i.to_string()]);
    }
    args.extend(["ui".into(), "--no-open".into(), "--service".into()]);
    args
}

fn home() -> Result<PathBuf> {
    dirs::home_dir().context("couldn't find your home folder")
}

fn systemd_unit_path() -> Result<PathBuf> {
    Ok(dirs::config_dir().context("couldn't find your config folder")?.join("systemd/user/nattowok.service"))
}

fn launch_agent_path() -> Result<PathBuf> {
    Ok(home()?.join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
}

/// systemd splits ExecStart on spaces unless an argument is quoted.
fn systemd_quote(arg: &str) -> String {
    if arg.chars().any(|c| c.is_whitespace() || c == '"' || c == '\\') {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

pub fn systemd_unit(exe: &Path, args: &[String]) -> String {
    let cmd: Vec<String> = std::iter::once(exe.display().to_string()).chain(args.iter().cloned()).collect();
    format!(
        "[Unit]\n\
         Description=NattoWok network watcher\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=30\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        cmd.iter().map(|a| systemd_quote(a)).collect::<Vec<_>>().join(" ")
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn launch_agent(exe: &Path, args: &[String], log: &Path) -> String {
    let program: String = std::iter::once(exe.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| format!("    <string>{}</string>\n", xml_escape(&a)))
        .collect();
    let log = xml_escape(&log.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{program}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#
    )
}

/// Windows quoting for a command line inside schtasks' /TR.
fn windows_quote(arg: &str) -> String {
    if arg.contains([' ', '\t', '"']) { format!("\"{}\"", arg.replace('"', "\\\"")) } else { arg.to_string() }
}

/// `conhost --headless` keeps a console window from popping up at log-on.
pub fn windows_task_command(exe: &Path, args: &[String]) -> String {
    let parts: Vec<String> = std::iter::once(exe.display().to_string()).chain(args.iter().cloned()).collect();
    format!("conhost.exe --headless {}", parts.iter().map(|a| windows_quote(a)).collect::<Vec<_>>().join(" "))
}

fn run(cmd: &mut Command) -> Result<String> {
    let shown = format!("{cmd:?}");
    let out = cmd.output().with_context(|| format!("couldn't run {shown}"))?;
    if !out.status.success() {
        bail!("{shown} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(unix)]
fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn install(data_dir: &Path, interface: Option<&str>) -> Result<String> {
    let exe = std::env::current_exe().context("couldn't find the nattowok program")?;
    let args = service_args(data_dir, interface);
    if cfg!(target_os = "macos") {
        #[cfg(unix)]
        {
            let path = launch_agent_path()?;
            std::fs::create_dir_all(path.parent().expect("has parent"))?;
            std::fs::create_dir_all(data_dir)?;
            std::fs::write(&path, launch_agent(&exe, &args, &data_dir.join("service.log")))?;
            let domain = format!("gui/{}", uid());
            // Replace an older copy if one is loaded.
            let _ = Command::new("launchctl").args(["bootout", &domain]).arg(&path).output();
            run(Command::new("launchctl").args(["bootstrap", &domain]).arg(&path))?;
            return Ok(format!("Installed a LaunchAgent at {}", path.display()));
        }
    }
    if cfg!(windows) {
        let tr = windows_task_command(&exe, &args);
        run(Command::new("schtasks")
            .args(["/Create", "/F", "/TN", TASK_NAME, "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", &tr]))?;
        run(Command::new("schtasks").args(["/Run", "/TN", TASK_NAME]))?;
        return Ok(format!("Created the scheduled task \"{TASK_NAME}\" (runs when you log in)"));
    }
    let path = systemd_unit_path()?;
    std::fs::create_dir_all(path.parent().expect("has parent"))?;
    std::fs::write(&path, systemd_unit(&exe, &args))?;
    let started = run(Command::new("systemctl").args(["--user", "daemon-reload"]))
        .and_then(|_| run(Command::new("systemctl").args(["--user", "enable", "--now", "nattowok.service"])));
    if let Err(e) = started {
        let _ = std::fs::remove_file(&path);
        return Err(e.context(
            "systemd user services aren't available here; run `nattowok ui --no-open` from your desktop's autostart instead",
        ));
    }
    Ok(format!("Installed a systemd user service at {}", path.display()))
}

pub fn uninstall() -> Result<String> {
    if cfg!(target_os = "macos") {
        #[cfg(unix)]
        {
            let path = launch_agent_path()?;
            let _ = Command::new("launchctl").args(["bootout", &format!("gui/{}", uid())]).arg(&path).output();
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
            return Ok("Removed the LaunchAgent.".into());
        }
    }
    if cfg!(windows) {
        let _ = Command::new("schtasks").args(["/End", "/TN", TASK_NAME]).output();
        run(Command::new("schtasks").args(["/Delete", "/F", "/TN", TASK_NAME]))?;
        return Ok("Removed the scheduled task.".into());
    }
    let path = systemd_unit_path()?;
    let _ = Command::new("systemctl").args(["--user", "disable", "--now", "nattowok.service"]).output();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).output();
    Ok("Removed the systemd user service.".into())
}

/// Whether the service is installed, as far as the OS says.
pub fn installed() -> bool {
    if cfg!(target_os = "macos") {
        return launch_agent_path().is_ok_and(|p| p.exists());
    }
    if cfg!(windows) {
        return Command::new("schtasks").args(["/Query", "/TN", TASK_NAME]).output().is_ok_and(|o| o.status.success());
    }
    systemd_unit_path().is_ok_and(|p| p.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_service_definitions() {
        let exe = Path::new("/opt/My Apps/nattowok");
        let args = service_args(Path::new("/home/kim/.local/share/nattowok"), Some("wlan0"));
        assert_eq!(args.last().map(String::as_str), Some("--service"));

        let unit = systemd_unit(exe, &args);
        assert!(unit.contains("ExecStart=\"/opt/My Apps/nattowok\" --data-dir /home/kim/.local/share/nattowok --interface wlan0 ui --no-open --service"));

        let plist = launch_agent(exe, &args, Path::new("/tmp/a&b.log"));
        assert!(plist.contains("<string>/opt/My Apps/nattowok</string>"));
        assert!(plist.contains("<string>--service</string>"));
        assert!(plist.contains("/tmp/a&amp;b.log"));

        let tr = windows_task_command(Path::new(r"C:\Program Files\NattoWok\nattowok.exe"), &args);
        assert!(tr.starts_with(r#"conhost.exe --headless "C:\Program Files\NattoWok\nattowok.exe" --data-dir"#));
    }
}
