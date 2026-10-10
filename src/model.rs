//! Data types shared by the scanner, the CLI and the web dashboard.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What kind of thing a device is, as best we can tell.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Router,
    Computer,
    Phone,
    Tablet,
    Wearable,
    Tv,
    Speaker,
    Printer,
    Camera,
    SmartHome,
    GameConsole,
    Nas,
    Server,
    VirtualMachine,
    Unknown,
}

impl DeviceKind {
    pub const ALL: [DeviceKind; 15] = [
        DeviceKind::Router,
        DeviceKind::Computer,
        DeviceKind::Phone,
        DeviceKind::Tablet,
        DeviceKind::Wearable,
        DeviceKind::Tv,
        DeviceKind::Speaker,
        DeviceKind::Printer,
        DeviceKind::Camera,
        DeviceKind::SmartHome,
        DeviceKind::GameConsole,
        DeviceKind::Nas,
        DeviceKind::Server,
        DeviceKind::VirtualMachine,
        DeviceKind::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            DeviceKind::Router => "Router / access point",
            DeviceKind::Computer => "Computer",
            DeviceKind::Phone => "Phone",
            DeviceKind::Tablet => "Tablet",
            DeviceKind::Wearable => "Wearable",
            DeviceKind::Tv => "TV / streaming",
            DeviceKind::Speaker => "Speaker / voice assistant",
            DeviceKind::Printer => "Printer / scanner",
            DeviceKind::Camera => "Camera",
            DeviceKind::SmartHome => "Smart home",
            DeviceKind::GameConsole => "Game console",
            DeviceKind::Nas => "Network storage",
            DeviceKind::Server => "Server / single-board computer",
            DeviceKind::VirtualMachine => "Virtual machine",
            DeviceKind::Unknown => "Unknown",
        }
    }
}

/// One reason we believe something about a device. Shown to people so the
/// identification is never a black box.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Evidence {
    pub source: String,
    pub detail: String,
    #[serde(default)]
    pub weight: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// A service a device advertises via mDNS / Bonjour.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Advertised {
    pub service: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UpnpInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Points deducted from the network health score.
    pub fn penalty(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 20,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// A security or hygiene observation, written for non-experts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    /// Stable identifier so people can dismiss a finding and not be nagged again.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// What it means, in plain language.
    pub explanation: String,
    /// What to do about it.
    pub fix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default)]
    pub ignored: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    /// MAC address when known (stable across IP changes), otherwise `ip:<addr>`.
    pub id: String,
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// The MAC is randomized (a privacy feature of modern phones and laptops).
    #[serde(default)]
    pub private_mac: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netbios_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Best human-readable name we could find, before any custom name.
    pub name: String,
    pub kind: DeviceKind,
    pub confidence: u8,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub open_ports: Vec<OpenPort>,
    #[serde(default)]
    pub advertised: Vec<Advertised>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upnp: Option<UpnpInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub is_gateway: bool,
    #[serde(default)]
    pub is_self: bool,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default = "default_true")]
    pub online: bool,
    // Fields below come from the person's inventory, not from the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub trusted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    /// Seen for the first time in the most recent scan.
    #[serde(default)]
    pub is_new: bool,
}

fn default_true() -> bool {
    true
}

impl Device {
    pub fn new(ip: Ipv4Addr, mac: Option<String>) -> Self {
        let id = mac.clone().unwrap_or_else(|| format!("ip:{ip}"));
        Device {
            id,
            ip,
            mac,
            vendor: None,
            private_mac: false,
            hostname: None,
            netbios_name: None,
            model: None,
            name: ip.to_string(),
            kind: DeviceKind::Unknown,
            confidence: 0,
            evidence: Vec::new(),
            open_ports: Vec::new(),
            advertised: Vec::new(),
            upnp: None,
            latency_ms: None,
            is_gateway: false,
            is_self: false,
            findings: Vec::new(),
            online: true,
            custom_name: None,
            notes: None,
            tags: Vec::new(),
            trusted: false,
            first_seen: None,
            last_seen: None,
            is_new: false,
        }
    }

    /// The name people should see: their own label first.
    pub fn display_name(&self) -> &str {
        self.custom_name.as_deref().unwrap_or(&self.name)
    }

    pub fn has_port(&self, port: u16) -> bool {
        self.open_ports.iter().any(|p| p.port == port)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NetworkInfo {
    pub interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_label: Option<String>,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    /// The range that was (or will be) scanned, e.g. `192.168.1.0/24`.
    pub scan_range: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_speed_mbps: Option<u64>,
    #[serde(default)]
    pub wireless: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ScanReport {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub network: NetworkInfo,
    pub devices: Vec<Device>,
    /// Network-wide findings (per-device ones live on each device too).
    pub findings: Vec<Finding>,
    pub health_score: u8,
    /// Things that limited this scan, e.g. a missing `ping` command.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ScanReport {
    /// Every finding, network-wide and per device.
    pub fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().chain(self.devices.iter().flat_map(|d| d.findings.iter()))
    }
}
