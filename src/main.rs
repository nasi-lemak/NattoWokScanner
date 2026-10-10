use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use nattowok::doctor::{self, Status};
use nattowok::model::{Device, ScanReport, Severity};
use nattowok::scan::{self, ScanOptions};
use nattowok::store::{DeviceUpdate, Event, Inventory, Workspace};
use nattowok::{netinfo, probe, report, web, wol};

/// See who's on your network, what they are, and whether anything needs fixing.
/// Runs entirely on this computer: no account, no cloud.
#[derive(Parser)]
#[command(name = "nattowok", version, about, long_about = None)]
struct Cli {
    /// Where the device inventory is kept [default: your OS data folder, or $NATTOWOK_DATA]
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Network interface to use (e.g. en0, wlan0, "Wi-Fi")
    #[arg(long, short = 'i', global = true, value_name = "NAME")]
    interface: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the dashboard in your browser (the default)
    Ui {
        /// Address to serve on. Anything other than localhost makes the dashboard reachable by others
        #[arg(long, default_value = "127.0.0.1:7878")]
        listen: SocketAddr,
        /// Don't open a browser
        #[arg(long)]
        no_open: bool,
        /// Start a scan right away
        #[arg(long)]
        scan: bool,
    },
    /// Scan the network and show what's on it
    Scan {
        #[command(flatten)]
        scan: ScanArgs,
        /// Print JSON instead of a table
        #[arg(long)]
        json: bool,
        /// Don't remember the results
        #[arg(long)]
        no_save: bool,
    },
    /// List every device NattoWok knows about, online or not
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Find out why the internet is slow or broken
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Check ~1,100 ports on one device
    Ports {
        /// Device name, IP or MAC
        device: String,
        #[arg(long)]
        json: bool,
    },
    /// Wake a sleeping computer with Wake-on-LAN
    Wake {
        /// Device name, IP or MAC
        device: String,
    },
    /// Name, tag, annotate or trust a device
    Label {
        /// Device name, IP or MAC
        device: String,
        #[arg(long)]
        name: Option<String>,
        /// Mark as a device you recognise
        #[arg(long, conflicts_with = "untrust")]
        trust: bool,
        #[arg(long)]
        untrust: bool,
        /// Replace the tags (repeat for several)
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove a device and its history
    Forget { device: String },
    /// Scan repeatedly and report changes; optionally run a command for each
    Watch {
        #[command(flatten)]
        scan: ScanArgs,
        /// Seconds between scans
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(30..))]
        interval: u64,
        /// Command to run when a new device joins. Details are passed as
        /// NATTOWOK_* environment variables, never spliced into the command
        #[arg(long, value_name = "CMD")]
        on_new_device: Option<String>,
        /// Command to run for every change
        #[arg(long, value_name = "CMD")]
        on_event: Option<String>,
    },
    /// Export the latest results
    Export {
        format: ExportFormat,
        /// Write to a file instead of the terminal
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// List the networks NattoWok remembers (each has its own devices)
    Networks,
    /// Show this computer's network settings
    Info {
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args, Clone)]
struct ScanArgs {
    /// Range to scan, e.g. 192.168.1.0/24 [default: your subnet]
    #[arg(long, short)]
    target: Option<String>,
    /// Skip checking for open ports (faster)
    #[arg(long)]
    no_ports: bool,
    /// How long to wait for each device, in milliseconds
    #[arg(long, default_value_t = 900)]
    timeout_ms: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    Csv,
    Md,
    Json,
}

struct Paint {
    on: bool,
}

impl Paint {
    fn new() -> Self {
        Paint { on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn blue(&self, s: &str) -> String {
        self.wrap("34", s)
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn scan_options(cli_interface: &Option<String>, args: &ScanArgs) -> ScanOptions {
    ScanOptions {
        interface: cli_interface.clone(),
        target: args.target.clone(),
        ports: !args.no_ports,
        timeout: Duration::from_millis(args.timeout_ms.clamp(100, 10_000)),
    }
}

fn terminal_progress() -> scan::Progress {
    if !std::io::stderr().is_terminal() {
        return scan::no_progress();
    }
    Arc::new(|phase: &str, p: f32| {
        let width = 24;
        let filled = ((p.clamp(0.0, 1.0) * width as f32) as usize).min(width);
        eprint!("\r\x1b[2K[{}{}] {phase}…", "█".repeat(filled), "·".repeat(width - filled));
        if p >= 1.0 {
            eprint!("\r\x1b[2K");
        }
        let _ = std::io::stderr().flush();
    })
}

async fn run(cli: Cli) -> Result<()> {
    let data_dir = cli.data_dir.clone().unwrap_or_else(nattowok::store::default_dir);
    let workspace = Workspace::new(data_dir.clone());
    let current = || workspace.load_current(cli.interface.as_deref());
    let paint = Paint::new();
    let command = cli.command.unwrap_or(Command::Ui { listen: "127.0.0.1:7878".parse()?, no_open: false, scan: false });
    match command {
        Command::Ui { listen, no_open, scan } => {
            web::serve(web::ServeOptions {
                listen,
                open_browser: !no_open,
                scan_on_start: scan,
                scan_opts: ScanOptions { interface: cli.interface.clone(), ..Default::default() },
                data_dir,
            })
            .await
        }
        Command::Scan { scan: args, json, no_save } => {
            let mut report = scan::run(&scan_options(&cli.interface, &args), terminal_progress()).await?;
            let events = if no_save {
                // Still compare against what we know, just don't write it down.
                let (_, mut inv) = workspace.load_current(cli.interface.as_deref())?;
                inv.apply_scan(&mut report)
            } else {
                workspace.record_scan(&mut report)?.2
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&paint, &report, &events);
            }
            Ok(())
        }
        Command::Devices { json } => {
            let (_, inv) = current()?;
            let Some(view) = inv.current_view() else {
                println!("No devices yet. Run `nattowok scan` first.");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&view.devices)?);
            } else {
                print_devices(&paint, &view.devices);
            }
            Ok(())
        }
        Command::Doctor { json } => {
            let diag = doctor::run(cli.interface.as_deref(), terminal_progress()).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diag)?);
                return Ok(());
            }
            let headline = match diag.status {
                Status::Pass | Status::Skip => paint.green(&diag.headline),
                Status::Warn => paint.yellow(&diag.headline),
                Status::Fail => paint.red(&diag.headline),
            };
            println!("\n  {}\n  {}\n", paint.bold(&headline), diag.summary);
            for c in &diag.checks {
                let mark = match c.status {
                    Status::Pass => paint.green("✓"),
                    Status::Skip => paint.dim("–"),
                    Status::Warn => paint.yellow("!"),
                    Status::Fail => paint.red("✗"),
                };
                println!("  {mark} {} {}", paint.bold(&c.title), paint.dim(&format!("({})", c.layer)));
                println!("    {}", c.detail);
                if let Some(a) = &c.advice {
                    println!("    {} {a}", paint.blue("→"));
                }
            }
            if !diag.dns.is_empty() {
                println!("\n  {}", paint.bold("DNS speed"));
                let mut dns = diag.dns.clone();
                dns.sort_by(|a, b| a.median_ms.unwrap_or(f64::MAX).total_cmp(&b.median_ms.unwrap_or(f64::MAX)));
                for d in dns {
                    let ms = d.median_ms.map_or("no answer".to_string(), |m| format!("{m} ms"));
                    let using = if d.configured { paint.blue(" (in use)") } else { String::new() };
                    println!("    {:<22} {:<16} {ms}{using}", d.label, d.server.to_string());
                }
            }
            println!();
            Ok(())
        }
        Command::Ports { device, json } => {
            let (_, inv) = current()?;
            let ip = match device.parse() {
                Ok(ip) => ip,
                Err(_) => resolve(&inv, &device)?.snapshot.ip,
            };
            eprintln!("Checking {} ports on {ip}…", probe::deep_ports().len());
            let limit = Arc::new(tokio::sync::Semaphore::new(256));
            let open = probe::scan_ports(ip, &probe::deep_ports(), Duration::from_millis(800), limit).await;
            let described = probe::describe_ports(ip, &open).await;
            if json {
                println!("{}", serde_json::to_string_pretty(&described)?);
            } else if described.is_empty() {
                println!("No open ports found on {ip}.");
            } else {
                for p in described {
                    let banner = p.banner.map(|b| paint.dim(&format!("  {b}"))).unwrap_or_default();
                    println!("  {:>5}  {}{banner}", p.port, p.service);
                }
            }
            Ok(())
        }
        Command::Wake { device } => {
            let (_, inv) = current()?;
            let mac = match nattowok::oui::normalize(&device) {
                Some(mac) => mac,
                None => {
                    resolve(&inv, &device)?.snapshot.mac.clone().context("that device's hardware address is unknown")?
                }
            };
            let broadcast = match netinfo::detect(cli.interface.as_deref(), None) {
                Ok(info) => netinfo::broadcast(&info),
                Err(_) => std::net::Ipv4Addr::BROADCAST,
            };
            wol::wake(&mac, broadcast).await?;
            println!("Sent a wake-up packet to {mac}. It may take a minute to boot.");
            Ok(())
        }
        Command::Label { device, name, trust, untrust, tags, note } => {
            let (key, mut inv) = current()?;
            let id = resolve(&inv, &device)?.id.clone();
            let update = DeviceUpdate {
                custom_name: name,
                notes: note,
                tags: (!tags.is_empty()).then_some(tags),
                trusted: if trust {
                    Some(true)
                } else if untrust {
                    Some(false)
                } else {
                    None
                },
            };
            let k = inv.update(&id, update).expect("resolved above");
            let label = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
            let trusted = k.trusted;
            workspace.save(&key, &inv)?;
            println!("Saved {label}{}.", if trusted { " (trusted)" } else { "" });
            Ok(())
        }
        Command::Forget { device } => {
            let (key, mut inv) = current()?;
            let id = resolve(&inv, &device)?.id.clone();
            inv.forget(&id);
            workspace.save(&key, &inv)?;
            println!("Forgot {id}.");
            Ok(())
        }
        Command::Watch { scan: args, interval, on_new_device, on_event } => {
            let opts = scan_options(&cli.interface, &args);
            println!("Watching the network every {interval} s. Press Ctrl+C to stop.");
            loop {
                match scan::run(&opts, scan::no_progress()).await {
                    Ok(mut report) => {
                        let (_, _, events) = workspace.record_scan(&mut report)?;
                        let stamp = chrono::Local::now().format("%H:%M:%S");
                        if events.is_empty() {
                            println!(
                                "{} {} devices online, no changes",
                                paint.dim(&stamp.to_string()),
                                report.devices.len()
                            );
                        }
                        for e in &events {
                            println!("{} {}", paint.dim(&stamp.to_string()), e.message);
                            let device =
                                e.device_id.as_ref().and_then(|id| report.devices.iter().find(|d| &d.id == id));
                            if let Some(cmd) = &on_event {
                                run_hook(cmd, e, device).await;
                            }
                            if let (Some(cmd), nattowok::store::EventKind::NewDevice) = (&on_new_device, e.kind) {
                                run_hook(cmd, e, device).await;
                            }
                        }
                    }
                    Err(e) => eprintln!("scan failed: {e:#}"),
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
        Command::Export { format, output } => {
            let (_, inv) = current()?;
            let view = inv.current_view().context("nothing to export yet; run `nattowok scan` first")?;
            let text = match format {
                ExportFormat::Csv => report::to_csv(&view),
                ExportFormat::Md => report::to_markdown(&view),
                ExportFormat::Json => serde_json::to_string_pretty(&view)?,
            };
            match output {
                Some(path) => {
                    std::fs::write(&path, text).with_context(|| format!("couldn't write {}", path.display()))?;
                    println!("Wrote {}", path.display());
                }
                None => print!("{text}"),
            }
            Ok(())
        }
        Command::Networks => {
            let (key, _) = current()?;
            let networks = workspace.networks(&key);
            if networks.is_empty() {
                println!("No networks scanned yet. Run `nattowok scan`.");
            }
            for n in networks {
                let marker = if n.current { paint.green("● current") } else { String::new() };
                let when = n
                    .last_scan
                    .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_default();
                println!(
                    "  {:<20} {:<18} router {:<15} {:>3} devices  last scan {when} {marker}",
                    n.key,
                    n.scan_range,
                    n.gateway.map(|g| g.to_string()).unwrap_or_default(),
                    n.devices
                );
            }
            Ok(())
        }
        Command::Info { json } => {
            let info = netinfo::detect(cli.interface.as_deref(), None)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
                return Ok(());
            }
            let row = |k: &str, v: String| println!("  {:<14} {v}", paint.dim(k));
            row(
                "Interface",
                format!(
                    "{}{}",
                    info.interface,
                    info.interface_label.as_ref().map(|l| format!(" ({l})")).unwrap_or_default()
                ),
            );
            row("Address", format!("{}/{}", info.ip, info.prefix));
            row("Scan range", info.scan_range.clone());
            row("MAC", info.mac.clone().unwrap_or_else(|| "unknown".into()));
            row("Router", info.gateway.map_or("none".into(), |g| g.to_string()));
            row("DNS", info.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
            if let Some(s) = info.link_speed_mbps {
                row("Link speed", format!("{s} Mbps"));
            }
            if let Some(m) = info.mtu {
                row("MTU", m.to_string());
            }
            row("Data folder", data_dir.display().to_string());
            row("Network id", workspace.key_for(Some(&info)));
            Ok(())
        }
    }
}

fn resolve<'a>(inv: &'a Inventory, query: &str) -> Result<&'a nattowok::store::KnownDevice> {
    match inv.resolve(query) {
        Some(k) => Ok(k),
        None if inv.devices.is_empty() => bail!("no devices known yet; run `nattowok scan` first"),
        None => bail!("no device matches {query:?}; use a name, IP or MAC from `nattowok devices`"),
    }
}

async fn run_hook(cmd: &str, event: &Event, device: Option<&Device>) {
    let mut c = if cfg!(windows) {
        let mut c = tokio::process::Command::new("cmd");
        c.args(["/C", cmd]);
        c
    } else {
        let mut c = tokio::process::Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    c.env(
        "NATTOWOK_EVENT",
        serde_json::to_value(event.kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
    )
    .env("NATTOWOK_MESSAGE", &event.message)
    .env("NATTOWOK_DEVICE_ID", event.device_id.clone().unwrap_or_default());
    if let Some(d) = device {
        c.env("NATTOWOK_DEVICE_NAME", d.display_name())
            .env("NATTOWOK_DEVICE_IP", d.ip.to_string())
            .env("NATTOWOK_DEVICE_MAC", d.mac.clone().unwrap_or_default())
            .env("NATTOWOK_DEVICE_VENDOR", d.vendor.clone().unwrap_or_default())
            .env("NATTOWOK_DEVICE_KIND", d.kind.label());
    }
    match c.status().await {
        Ok(s) if !s.success() => eprintln!("hook exited with {s}"),
        Err(e) => eprintln!("couldn't run hook: {e}"),
        _ => {}
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

fn print_devices(paint: &Paint, devices: &[Device]) {
    // Pad before colouring, or the escape codes throw the columns off.
    println!(
        "  {}",
        paint.bold(&format!("{:<28} {:<24} {:<15} {:<24} {}", "Name", "Type", "IP", "Made by / model", "Status"))
    );
    for d in devices {
        let what = d
            .model
            .clone()
            .or_else(|| d.vendor.clone())
            .unwrap_or_else(|| if d.private_mac { "private address".into() } else { "?".into() });
        let mut status = Vec::new();
        if d.is_self {
            status.push(paint.green("this computer"));
        }
        if d.is_gateway {
            status.push(paint.blue("router"));
        }
        if d.is_new {
            status.push(paint.red("NEW"));
        }
        let issues = d.findings.iter().filter(|f| !f.ignored && f.severity > Severity::Info).count();
        if issues > 0 {
            status.push(paint.yellow(&format!("{issues} issue{}", if issues == 1 { "" } else { "s" })));
        }
        if !d.online {
            status.push(paint.dim("offline"));
        } else if d.trusted && !d.is_self {
            status.push(paint.green("trusted"));
        } else if !d.is_self && !d.is_gateway {
            status.push(paint.dim("not reviewed"));
        }
        let kind = if d.confidence > 0 && d.confidence < 45 {
            format!("{}?", d.kind.label())
        } else {
            d.kind.label().to_string()
        };
        println!(
            "  {:<28} {:<24} {:<15} {:<24} {}",
            truncate(d.display_name(), 27),
            truncate(&kind, 23),
            d.ip,
            truncate(&what, 23),
            status.join(", ")
        );
    }
}

fn print_report(paint: &Paint, report: &ScanReport, events: &[Event]) {
    let n = &report.network;
    println!(
        "\n  {} {} devices on {} {}\n",
        paint.bold("Found"),
        report.devices.len(),
        n.scan_range,
        paint.dim(&format!(
            "(took {:.1}s)",
            (report.finished_at - report.started_at).num_milliseconds() as f64 / 1000.0
        ))
    );
    print_devices(paint, &report.devices);

    let mut findings: Vec<_> = report.all_findings().filter(|f| !f.ignored && f.severity > Severity::Info).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let score = report.health_score;
    let score_text = format!("{score}/100");
    let score_text = if score >= 85 {
        paint.green(&score_text)
    } else if score >= 60 {
        paint.yellow(&score_text)
    } else {
        paint.red(&score_text)
    };
    println!("\n  {} {score_text}", paint.bold("Health score"));
    for f in findings {
        let sev = match f.severity {
            Severity::High => paint.red("HIGH  "),
            Severity::Medium => paint.yellow("MEDIUM"),
            _ => paint.dim("LOW   "),
        };
        println!("  {sev} {}", f.title);
        println!("         {} {}", paint.blue("→"), f.fix);
    }
    if !events.is_empty() {
        println!("\n  {}", paint.bold("Changes"));
        for e in events {
            println!("  • {}", e.message);
        }
    }
    for note in &report.notes {
        println!("\n  {} {note}", paint.dim("note:"));
    }
    let unreviewed = report.devices.iter().filter(|d| !d.trusted && !d.is_self && !d.is_gateway).count();
    if unreviewed > 0 {
        println!(
            "\n  {}",
            paint.dim(&format!("Tip: `nattowok label <name|ip> --trust --name \"…\"` marks devices you recognise ({unreviewed} not reviewed). Or run `nattowok` for the dashboard."))
        );
    }
    println!();
}
