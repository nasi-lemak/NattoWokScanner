//! Native desktop notifications, using what each OS already has, so there
//! is nothing extra to install.
//!
//! Text is always passed as separate arguments or environment variables,
//! never spliced into a script, so a device can't inject commands through
//! its name.

use anyhow::{Result, bail};

use crate::store::{Event, EventKind};

/// Events worth interrupting someone for.
pub fn is_important(kind: EventKind) -> bool {
    matches!(kind, EventKind::NewDevice | EventKind::NewFinding | EventKind::NewOpenPort)
}

/// One notification per important event, or a single summary when there
/// are many (nobody wants twelve pop-ups after a holiday).
pub fn summarize(events: &[Event]) -> Vec<(String, String)> {
    let important: Vec<&Event> = events.iter().filter(|e| is_important(e.kind)).collect();
    let title = |e: &Event| match e.kind {
        EventKind::NewDevice => "New device on your network",
        EventKind::NewFinding => "New security issue",
        _ => "Something changed on your network",
    };
    if important.len() <= 3 {
        return important.iter().map(|e| (title(e).to_string(), e.message.clone())).collect();
    }
    let mut body: Vec<String> = important.iter().take(3).map(|e| e.message.clone()).collect();
    body.push(format!("…and {} more. Open NattoWok to see everything.", important.len() - 3));
    vec![(format!("{} changes on your network", important.len()), body.join("\n"))]
}

const WINDOWS_TOAST: &str = r#"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:NATTOWOK_TITLE)) > $null
$x.Item(1).AppendChild($t.CreateTextNode($env:NATTOWOK_BODY)) > $null
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))
"#;

/// Shows a desktop notification.
pub async fn send(title: &str, body: &str) -> Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = tokio::process::Command::new("osascript");
        c.args(["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)"])
            .args(["-e", "end run", title, body]);
        c
    } else if cfg!(windows) {
        let mut c = tokio::process::Command::new("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", WINDOWS_TOAST])
            .env("NATTOWOK_TITLE", title)
            .env("NATTOWOK_BODY", body);
        c
    } else {
        let mut c = tokio::process::Command::new("notify-send");
        c.args(["--app-name=NattoWok", "--icon=network-wireless", title, body]);
        c
    };
    let out = cmd.output().await.map_err(|e| {
        let tool = if cfg!(target_os = "macos") {
            "osascript"
        } else if cfg!(windows) {
            "PowerShell"
        } else {
            "notify-send (install libnotify-bin / libnotify)"
        };
        anyhow::anyhow!("couldn't show a notification: {tool} isn't available ({e})")
    })?;
    if !out.status.success() {
        bail!("the notification didn't show: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Sends notifications for important events, logging (not failing) errors.
pub async fn send_for(events: &[Event]) {
    for (title, body) in summarize(events) {
        if let Err(e) = send(&title, &body).await {
            eprintln!("{e:#}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn event(kind: EventKind, msg: &str) -> Event {
        Event { at: Utc::now(), kind, device_id: None, message: msg.into() }
    }

    #[test]
    fn only_important_events_notify() {
        let events =
            vec![event(EventKind::WentOffline, "TV went offline"), event(EventKind::NewDevice, "New device joined: X")];
        let n = summarize(&events);
        assert_eq!(n, vec![("New device on your network".to_string(), "New device joined: X".to_string())]);
    }

    #[test]
    fn many_events_become_one_summary() {
        let events: Vec<Event> = (0..6).map(|i| event(EventKind::NewDevice, &format!("device {i}"))).collect();
        let n = summarize(&events);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].0, "6 changes on your network");
        assert!(n[0].1.contains("and 3 more"));
    }
}
