//! Alerts on your phone, through a service you choose: ntfy, Telegram,
//! Discord, or any webhook (Home Assistant, Node-RED, your own script).
//!
//! Off until someone adds a target. Only the alert text ("New device joined:
//! Galaxy S23 at 192.168.1.40") is sent, to the one service picked.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::notify;
use crate::store::Event;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertTarget {
    /// A topic URL such as `https://ntfy.sh/nattowok-3f9c…`.
    Ntfy {
        url: String,
    },
    Telegram {
        bot_token: String,
        chat_id: String,
    },
    Discord {
        webhook_url: String,
    },
    /// Receives a JSON POST with the title, message and events.
    Webhook {
        url: String,
    },
}

fn mask(secret: &str) -> String {
    let tail: String = secret.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

impl AlertTarget {
    /// For showing in lists without revealing the secret parts.
    pub fn describe(&self) -> String {
        match self {
            AlertTarget::Ntfy { url } => match url.rsplit_once('/') {
                Some((server, topic)) => format!("ntfy: {server}/{}", mask(topic)),
                None => "ntfy".into(),
            },
            AlertTarget::Telegram { chat_id, .. } => format!("Telegram chat {}", mask(chat_id)),
            AlertTarget::Discord { .. } => "Discord channel webhook".into(),
            AlertTarget::Webhook { url } => {
                let host = url.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or(url);
                format!("Webhook to {host}")
            }
        }
    }

    /// Catches typos before the first alert is lost.
    pub fn validate(&self) -> Result<()> {
        let url_ok = |u: &str| u.starts_with("https://") || u.starts_with("http://");
        match self {
            AlertTarget::Ntfy { url } => {
                anyhow::ensure!(
                    url_ok(url),
                    "the ntfy address must start with https:// (e.g. https://ntfy.sh/your-topic)"
                );
                let topic = url.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                anyhow::ensure!(
                    !topic.is_empty() && !topic.contains('.') && topic.len() >= 6,
                    "add a topic to the address, e.g. https://ntfy.sh/your-topic"
                );
            }
            AlertTarget::Telegram { bot_token, chat_id } => {
                anyhow::ensure!(
                    bot_token.contains(':'),
                    "a Telegram bot token looks like 123456:ABC… (from @BotFather)"
                );
                anyhow::ensure!(!chat_id.trim().is_empty(), "a Telegram chat id is needed");
            }
            AlertTarget::Discord { webhook_url } => anyhow::ensure!(
                webhook_url.starts_with("https://discord.com/api/webhooks/")
                    || webhook_url.starts_with("https://discordapp.com/api/webhooks/"),
                "a Discord webhook address starts with https://discord.com/api/webhooks/"
            ),
            AlertTarget::Webhook { url } => {
                anyhow::ensure!(url_ok(url), "the webhook address must start with http:// or https://")
            }
        }
        Ok(())
    }
}

/// A hard-to-guess ntfy topic: anyone who knows a topic name can read it.
pub fn random_ntfy_url() -> String {
    let mut b = [0u8; 10];
    let _ = getrandom::fill(&mut b);
    format!("https://ntfy.sh/nattowok-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

/// The request each service expects: (url, JSON body).
pub fn build_request(target: &AlertTarget, title: &str, body: &str, events: &[Event]) -> Result<(String, String)> {
    Ok(match target {
        AlertTarget::Ntfy { url } => {
            // JSON publishing handles any characters in titles, unlike headers.
            let (server, topic) = url.trim_end_matches('/').rsplit_once('/').context("bad ntfy address")?;
            let tags = if title.contains("security") { ["warning"] } else { ["satellite"] };
            (server.to_string(), json!({ "topic": topic, "title": title, "message": body, "tags": tags }).to_string())
        }
        AlertTarget::Telegram { bot_token, chat_id } => (
            format!("https://api.telegram.org/bot{bot_token}/sendMessage"),
            json!({ "chat_id": chat_id, "text": format!("{title}\n{body}"), "disable_web_page_preview": true }).to_string(),
        ),
        AlertTarget::Discord { webhook_url } => (
            webhook_url.clone(),
            json!({ "username": "NattoWok", "content": format!("**{title}**\n{body}"), "allowed_mentions": { "parse": [] } })
                .to_string(),
        ),
        AlertTarget::Webhook { url } => (
            url.clone(),
            json!({ "source": "nattowok", "title": title, "message": body, "events": events }).to_string(),
        ),
    })
}

async fn post(url: &str, json: &str) -> Result<()> {
    let (status, text) = if let Some(rest) = url.strip_prefix("http://") {
        let (authority, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
        let addr = tokio::net::lookup_host(if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        })
        .await?
        .next()
        .context("couldn't look up the webhook address")?;
        let r = crate::http::post(
            addr,
            authority,
            &path,
            &[("Content-Type", "application/json")],
            json,
            std::time::Duration::from_secs(10),
        )
        .await?;
        (r.status, r.body)
    } else {
        #[cfg(feature = "tls")]
        {
            crate::fetch::post_json(url, json).await?
        }
        #[cfg(not(feature = "tls"))]
        bail!("this build can only send alerts to http:// addresses")
    };
    if !(200..300).contains(&status) {
        bail!("the service answered {status}: {}", text.chars().take(200).collect::<String>());
    }
    Ok(())
}

pub async fn send(target: &AlertTarget, title: &str, body: &str, events: &[Event]) -> Result<()> {
    let (url, json) = build_request(target, title, body, events)?;
    post(&url, &json).await.with_context(|| format!("{} failed", target.describe()))
}

/// Sends important events to every target, reporting (not failing on) errors.
pub async fn send_all(targets: &[AlertTarget], events: &[Event]) {
    let important: Vec<Event> = events.iter().filter(|e| notify::is_important(e.kind)).cloned().collect();
    for (title, body) in notify::summarize(&important) {
        for t in targets {
            if let Err(e) = send(t, &title, &body, &important).await {
                eprintln!("alert: {e:#}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_masks() {
        let ntfy = AlertTarget::Ntfy { url: "https://ntfy.sh/nattowok-0011223344".into() };
        ntfy.validate().unwrap();
        assert_eq!(ntfy.describe(), "ntfy: https://ntfy.sh/…3344");
        assert!(AlertTarget::Ntfy { url: "https://ntfy.sh".into() }.validate().is_err());
        assert!(AlertTarget::Discord { webhook_url: "https://evil.example/x".into() }.validate().is_err());
        let tg = AlertTarget::Telegram { bot_token: "123:ABC".into(), chat_id: "987654321".into() };
        tg.validate().unwrap();
        assert!(!tg.describe().contains("ABC"));
        assert!(random_ntfy_url().starts_with("https://ntfy.sh/nattowok-"));
    }

    #[test]
    fn builds_service_requests() {
        let (url, body) = build_request(
            &AlertTarget::Ntfy { url: "https://ntfy.sh/topic-abc".into() },
            "New device",
            "Kim’s phone 📱",
            &[],
        )
        .unwrap();
        assert_eq!(url, "https://ntfy.sh");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["topic"], "topic-abc");
        assert_eq!(v["message"], "Kim’s phone 📱");

        let (url, body) =
            build_request(&AlertTarget::Telegram { bot_token: "1:X".into(), chat_id: "42".into() }, "T", "B", &[])
                .unwrap();
        assert_eq!(url, "https://api.telegram.org/bot1:X/sendMessage");
        assert!(body.contains("\"chat_id\":\"42\""));

        let (_, body) = build_request(
            &AlertTarget::Discord { webhook_url: "https://discord.com/api/webhooks/1/x".into() },
            "T",
            "@everyone",
            &[],
        )
        .unwrap();
        assert!(body.contains("\"parse\":[]"), "mentions must be disabled: {body}");
    }

    /// A pretend Home Assistant receives the JSON over plain HTTP.
    #[tokio::test]
    async fn posts_to_a_local_webhook() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&req).contains("\"source\":\"nattowok\"") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            String::from_utf8_lossy(&req).into_owned()
        });
        let target = AlertTarget::Webhook { url: format!("http://127.0.0.1:{port}/api/webhook/nattowok") };
        send(&target, "New device on your network", "New device joined: X", &[]).await.unwrap();
        let req = server.await.unwrap();
        assert!(req.starts_with("POST /api/webhook/nattowok HTTP/1.1"));
        assert!(req.contains("New device joined: X"));
    }
}
