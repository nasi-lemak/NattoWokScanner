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
use nattowok::{netinfo, probe, report, room, web, wol};

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
        /// Set by the background service
        #[arg(long, hide = true)]
        service: bool,
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
    /// Look for hidden cameras on the Wi-Fi of a rental or hotel room.
    /// Only finds devices: never logs in to them or opens their video.
    /// Not saved to your device list
    #[command(alias = "sweep")]
    RoomCheck {
        #[arg(long)]
        json: bool,
    },
    /// Test download/upload speed and lag under load (uses Cloudflare's speed test)
    Speed {
        #[arg(long)]
        json: bool,
        /// Show past results instead of running a test
        #[arg(long)]
        history: bool,
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
        /// Correct the device type: router, computer, phone, tablet, wearable,
        /// tv, speaker, printer, camera, smart_home, game_console, nas, server,
        /// virtual_machine, unknown, or `auto` to go back to detection
        #[arg(long, value_name = "TYPE")]
        kind: Option<String>,
    },
    /// Remove a device and its history
    Forget { device: String },
    /// Say two entries are one device (e.g. a phone that changed its private
    /// address); the older entry's name, notes and history move to the first
    Merge {
        /// The device as it is now (name, IP or MAC)
        device: String,
        /// The earlier entry it should take over
        earlier: String,
    },
    /// Watch devices answer in real time. Unplug something and see which one
    /// stops answering: the easy way to work out what a mystery device is
    Live {
        /// Seconds between checks
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
    },
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
        /// Show a desktop notification for new devices and security issues
        #[arg(long)]
        notify: bool,
    },
    /// Open the dashboard on your phone: shows a link and QR code
    Phone {
        /// Turn phone access off
        #[arg(long, conflicts_with = "new_link")]
        off: bool,
        /// Make a new link; the old one stops working
        #[arg(long)]
        new_link: bool,
    },
    /// Get alerts on your phone (ntfy, Telegram, Discord or a webhook)
    Alerts {
        #[command(subcommand)]
        action: AlertAction,
    },
    /// Keep NattoWok running in the background (starts when you log in),
    /// scanning on a schedule and notifying you about changes
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Export the latest results
    Export {
        format: ExportFormat,
        /// Write to a file instead of the terminal
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Where your router keeps the settings NattoWok suggests changing
    Router,
    /// Who's home, going by when their phones are on the network
    Home,
    /// List the networks NattoWok remembers (each has its own devices)
    Networks,
    /// Download the latest manufacturer list from the IEEE (about 4 MB)
    UpdateVendors,
    /// Show this computer's network settings
    Info {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AlertAction {
    /// Show where alerts go
    List,
    /// Send alerts to ntfy (free phone app). Without a topic, a private one is made for you
    Ntfy {
        /// A topic name or full address like https://ntfy.sh/my-topic
        topic: Option<String>,
    },
    /// Send alerts to a Telegram chat through your own bot (from @BotFather)
    Telegram {
        #[arg(long)]
        token: String,
        #[arg(long)]
        chat: String,
    },
    /// Send alerts to a Discord channel webhook
    Discord { webhook_url: String },
    /// POST alerts as JSON to any address (Home Assistant, Node-RED, your script)
    Webhook { url: String },
    /// Stop sending to the target with this number (from `alerts list`)
    Remove { number: usize },
    /// Send a test alert to every target
    Test,
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and start the background service
    Install {
        /// Minutes between automatic scans
        #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u32).range(5..=1440))]
        every: u32,
        /// Don't show desktop notifications
        #[arg(long)]
        no_notifications: bool,
    },
    /// Stop and remove the background service
    Uninstall,
    /// Show whether the service is installed and running
    Status,
    /// Show a test notification
    TestNotification,
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
    /// Scrubbed of names and addresses, for helping improve detection
    #[value(alias = "anonymized")]
    Anonymised,
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
    nattowok::oui::init(&data_dir);
    let current = || workspace.load_current(cli.interface.as_deref());
    let paint = Paint::new();
    let command = cli.command.unwrap_or(Command::Ui {
        listen: "127.0.0.1:7878".parse()?,
        no_open: false,
        scan: false,
        service: false,
    });
    match command {
        Command::Ui { listen, no_open, scan, service } => {
            web::serve(web::ServeOptions {
                listen,
                open_browser: !no_open,
                scan_on_start: scan,
                service_mode: service,
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
                print_devices(&paint, &view.devices, &view.findings);
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
        #[cfg(not(feature = "tls"))]
        Command::Speed { .. } => bail!("this build of NattoWok has no speed test (built without the `tls` feature)"),
        #[cfg(feature = "tls")]
        Command::Speed { json, history } => {
            use nattowok::speedtest;
            if history {
                let past = speedtest::load_history(&data_dir);
                if json {
                    println!("{}", serde_json::to_string_pretty(&past)?);
                } else if past.is_empty() {
                    println!("No speed tests yet. Run `nattowok speed`.");
                }
                for r in past.iter().filter(|_| !json) {
                    println!(
                        "  {}  ↓ {:>7.1} Mbps  ↑ {:>7.1} Mbps  idle {:>5.1} ms  busy {:>6.1} ms  grade {:?}",
                        r.at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
                        r.download_mbps,
                        r.upload_mbps,
                        r.idle_ms,
                        r.loaded_down_ms.max(r.loaded_up_ms),
                        r.grade
                    );
                }
                return Ok(());
            }
            if !json {
                eprintln!(
                    "Testing with Cloudflare's speed test. This takes about 15 seconds and uses up to about 450 MB of data (more on multi-gigabit lines)."
                );
            }
            let r = speedtest::run(&speedtest::SpeedOptions::default(), terminal_progress()).await?;
            speedtest::save_result(&data_dir, &r)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
                return Ok(());
            }
            let grade = format!("{:?}", r.grade);
            let grade = match r.grade {
                speedtest::Grade::A | speedtest::Grade::B => paint.green(&grade),
                speedtest::Grade::C => paint.yellow(&grade),
                _ => paint.red(&grade),
            };
            println!("\n  {}  {:.1} Mbps", paint.bold("Download"), r.download_mbps);
            println!("  {}    {:.1} Mbps", paint.bold("Upload"), r.upload_mbps);
            println!(
                "  {}   {:.1} ms idle, {:.1} ms while downloading, {:.1} ms while uploading",
                paint.bold("Latency"),
                r.idle_ms,
                r.loaded_down_ms,
                r.loaded_up_ms
            );
            println!("  {}  {grade} (how much lag grows when the line is busy)", paint.bold("Responsiveness"));
            println!("\n  {}", r.verdict);
            if let Some(a) = &r.advice {
                println!("  {} {a}", paint.blue("→"));
            }
            println!(
                "  {}\n",
                paint.dim(&format!(
                    "Used {:.0} MB{}",
                    r.data_used_mb,
                    r.location.as_deref().map(|l| format!(" · server: Cloudflare {l}")).unwrap_or_default()
                ))
            );
            Ok(())
        }
        Command::RoomCheck { json } => {
            let opts = ScanOptions { interface: cli.interface.clone(), ..Default::default() };
            let check = room::run(&opts, terminal_progress(), &data_dir).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&check)?);
            } else {
                print_room_check(&paint, &check);
            }
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
        Command::Label { device, name, trust, untrust, tags, note, kind } => {
            if let Some(k) = kind.as_deref().filter(|k| *k != "auto") {
                anyhow::ensure!(
                    nattowok::store::parse_kind(k).is_some(),
                    "{k:?} isn't a device type; see `nattowok label --help`"
                );
            }
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
                kind,
            };
            let k = inv.update(&id, update).expect("resolved above");
            let label = k.custom_name.clone().unwrap_or_else(|| k.snapshot.name.clone());
            let trusted = k.trusted;
            workspace.save(&key, &inv)?;
            println!("Saved {label}{}.", if trusted { " (trusted)" } else { "" });
            Ok(())
        }
        Command::Merge { device, earlier } => {
            let (key, mut inv) = current()?;
            let keep = resolve(&inv, &device)?.id.clone();
            let from = resolve(&inv, &earlier)?.id.clone();
            let name = inv.merge(&keep, &from)?;
            workspace.save(&key, &inv)?;
            println!("Merged. {name} keeps its name and history.");
            Ok(())
        }
        Command::Live { interval } => {
            let (_, inv) = current()?;
            let view = inv.current_view().context("no devices known yet; run `nattowok scan` first")?;
            let devices: Vec<Device> = view.devices.into_iter().filter(|d| !d.is_self).collect();
            let targets: Vec<_> = devices
                .iter()
                .map(|d| (d.id.clone(), d.ip, d.open_ports.iter().map(|p| p.port).collect::<Vec<u16>>()))
                .collect();
            let name_of = |id: &str| {
                devices
                    .iter()
                    .find(|d| d.id == id)
                    .map(|d| format!("{} ({})", d.display_name(), d.ip))
                    .unwrap_or_default()
            };
            println!(
                "Checking {} devices every {interval} s. Unplug or switch something off and watch which one stops answering. Ctrl+C to stop.\n",
                devices.len()
            );
            let mut last: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
            loop {
                let results = probe::check_many(targets.clone(), Duration::from_millis(900)).await;
                let stamp = chrono::Local::now().format("%H:%M:%S").to_string();
                if last.is_empty() {
                    let silent: Vec<String> =
                        results.iter().filter(|(_, r)| r.is_none()).map(|(id, _)| name_of(id)).collect();
                    let up = results.len() - silent.len();
                    println!("{} {up} answering now.", paint.dim(&stamp));
                    if !silent.is_empty() {
                        println!(
                            "{} Not answering (offline, or doesn't respond to quick checks): {}",
                            paint.dim(&stamp),
                            silent.join(", ")
                        );
                    }
                }
                for (id, rtt) in &results {
                    let up = rtt.is_some();
                    if let Some(&was) = last.get(id) {
                        if was && !up {
                            println!("{} {} {} stopped answering", paint.dim(&stamp), paint.red("●"), name_of(id));
                        } else if !was && up {
                            println!("{} {} {} is answering again", paint.dim(&stamp), paint.green("●"), name_of(id));
                        }
                    }
                    last.insert(id.clone(), up);
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
        Command::Forget { device } => {
            let (key, mut inv) = current()?;
            let id = resolve(&inv, &device)?.id.clone();
            inv.forget(&id);
            workspace.save(&key, &inv)?;
            println!("Forgot {id}.");
            Ok(())
        }
        Command::Watch { scan: args, interval, on_new_device, on_event, notify } => {
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
                        if notify {
                            nattowok::notify::send_for(&events).await;
                        }
                        let targets = nattowok::settings::Settings::load(&data_dir).alerts;
                        nattowok::alerts::send_all(&targets, &events).await;
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
                ExportFormat::Anonymised => report::to_anonymised_json(&view),
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
        Command::Phone { off, new_link } => {
            let mut settings = nattowok::settings::Settings::load(&data_dir);
            if off {
                settings.phone_access = false;
                settings.save(&data_dir)?;
                println!("Phone access is off. A running NattoWok stops accepting phones within 20 seconds.");
                return Ok(());
            }
            settings.phone_access = true;
            if new_link || settings.phone_key.is_none() {
                settings.phone_key = Some(web::random_token());
            }
            settings.save(&data_dir)?;
            let ip = netinfo::detect(cli.interface.as_deref(), None)?.ip;
            let url = format!("http://{ip}:7878/?key={}", settings.phone_key.as_deref().unwrap_or_default());
            let code = qrcode::QrCode::new(url.as_bytes())?;
            let qr = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("\n{qr}\n");
            println!("  Scan this with your phone's camera, or open: {url}\n");
            println!("  {}", paint.dim("Your phone must be on the same Wi-Fi, and NattoWok must be running here (`nattowok` or the background service)."));
            println!("  {}", paint.dim("Anyone on your network with this link can use the dashboard. `nattowok phone --new-link` replaces it; `--off` turns it off."));
            Ok(())
        }
        Command::Alerts { action } => {
            use nattowok::alerts::{self, AlertTarget};
            let mut settings = nattowok::settings::Settings::load(&data_dir);
            let target = match action {
                AlertAction::List => {
                    if settings.alerts.is_empty() {
                        println!("No phone alerts set up. Try `nattowok alerts ntfy` (free app, no account).");
                    }
                    for (i, t) in settings.alerts.iter().enumerate() {
                        println!("  {}. {}", i + 1, t.describe());
                    }
                    return Ok(());
                }
                AlertAction::Remove { number } => {
                    anyhow::ensure!(number >= 1 && number <= settings.alerts.len(), "there's no alert target {number}");
                    let removed = settings.alerts.remove(number - 1);
                    settings.save(&data_dir)?;
                    println!("Removed {}.", removed.describe());
                    return Ok(());
                }
                AlertAction::Test => {
                    anyhow::ensure!(!settings.alerts.is_empty(), "no alert targets yet");
                    for t in &settings.alerts {
                        match alerts::send(t, "NattoWok test", "Alerts from NattoWok will arrive here.", &[]).await {
                            Ok(()) => println!("  {} {}", paint.green("✓"), t.describe()),
                            Err(e) => println!("  {} {e:#}", paint.red("✗")),
                        }
                    }
                    return Ok(());
                }
                AlertAction::Ntfy { topic } => AlertTarget::Ntfy {
                    url: match topic {
                        None => alerts::random_ntfy_url(),
                        Some(t) if t.starts_with("http") => t,
                        Some(t) => format!("https://ntfy.sh/{t}"),
                    },
                },
                AlertAction::Telegram { token, chat } => AlertTarget::Telegram { bot_token: token, chat_id: chat },
                AlertAction::Discord { webhook_url } => AlertTarget::Discord { webhook_url },
                AlertAction::Webhook { url } => AlertTarget::Webhook { url },
            };
            target.validate()?;
            if let AlertTarget::Ntfy { url } = &target {
                println!(
                    "Install the ntfy app (or open {url} in a browser) and subscribe to this address:\n\n    {url}\n"
                );
                println!("Keep it private: anyone who knows the address can read the alerts.");
            }
            settings.alerts.push(target);
            settings.save(&data_dir)?;
            println!(
                "Saved. Alerts are sent for new devices, new open ports and new security issues found by automatic scans (`nattowok service install`) or `nattowok watch`. Try `nattowok alerts test`."
            );
            Ok(())
        }
        Command::Service { action } => match action {
            ServiceAction::Install { every, no_notifications } => {
                let what = nattowok::service::install(&data_dir, cli.interface.as_deref())?;
                let mut settings = nattowok::settings::Settings::load(&data_dir);
                settings.auto_scan_minutes = every;
                settings.notifications = !no_notifications;
                settings.save(&data_dir)?;
                println!("{what}.");
                println!(
                    "NattoWok now runs in the background and scans every {every} minutes{}.",
                    if no_notifications { "" } else { ", notifying you about new devices and security issues" }
                );
                println!("Dashboard: http://localhost:7878/  (running `nattowok` opens it too)");
                if !no_notifications
                    && let Err(e) = nattowok::notify::send(
                        "NattoWok is watching your network",
                        "You'll get a notification when something new joins.",
                    )
                    .await
                {
                    println!("{} {e:#}", paint.yellow("Notifications may not work:"));
                }
                Ok(())
            }
            ServiceAction::Uninstall => {
                println!("{}", nattowok::service::uninstall()?);
                Ok(())
            }
            ServiceAction::Status => {
                let installed = nattowok::service::installed();
                let settings = nattowok::settings::Settings::load(&data_dir);
                let running =
                    nattowok::http::get("127.0.0.1:7878".parse()?, "localhost:7878", "/", Duration::from_secs(2))
                        .await
                        .is_ok_and(|r| r.body.contains("nattowok-token"));
                let yes_no = |b: bool| if b { paint.green("yes") } else { paint.dim("no") };
                println!("  Installed       {}", yes_no(installed));
                println!("  Dashboard up    {}", yes_no(running));
                println!(
                    "  Auto-scan       {}",
                    if settings.auto_scan_minutes == 0 {
                        "off".to_string()
                    } else {
                        format!("every {} min", settings.auto_scan_minutes)
                    }
                );
                println!("  Notifications   {}", yes_no(settings.notifications));
                Ok(())
            }
            ServiceAction::TestNotification => {
                nattowok::notify::send("NattoWok test", "If you can see this, notifications work.").await?;
                println!("Sent. If nothing appeared, check your system's notification settings.");
                Ok(())
            }
        },
        Command::Router => {
            let (_, inv) = current()?;
            let view = inv.current_view().context("no devices known yet; run `nattowok scan` first")?;
            let g = view.router_guide.context("NattoWok hasn't found your router yet; run `nattowok scan`")?;
            println!("\n  {} {}", paint.bold("Router:"), g.brand);
            println!("  {} {}", paint.bold("Settings:"), g.admin_url);
            if let Some(app) = &g.app {
                println!("  {} {app}", paint.bold("App:"));
            }
            println!();
            use nattowok::model::FixTopic::*;
            for (topic, label) in [
                (Upnp, "Turn off UPnP"),
                (GuestNetwork, "Guest / IoT network"),
                (Sqm, "Smart queue (fix lag under load)"),
                (WifiSecurity, "Wi-Fi security"),
                (WifiChannel, "Wi-Fi channel"),
                (Firmware, "Update firmware"),
            ] {
                if let Some(step) = g.steps.get(&topic) {
                    println!("  {}\n    {step}", paint.bold(label));
                }
            }
            println!("\n  {}\n", paint.dim("Menu names vary between firmware versions."));
            Ok(())
        }
        Command::Home => {
            let (_, inv) = current()?;
            let view = inv.current_view().context("no devices known yet; run `nattowok scan` first")?;
            let people: Vec<&Device> = view
                .devices
                .iter()
                .filter(|d| {
                    use nattowok::model::DeviceKind::*;
                    matches!(d.kind, Phone | Tablet | Wearable) && (d.trusted || d.custom_name.is_some())
                })
                .collect();
            if people.is_empty() {
                println!(
                    "Name your household's phones (`nattowok label <phone> --name \"Kim\" --trust`) to see who's home."
                );
                return Ok(());
            }
            let local =
                |t: chrono::DateTime<chrono::Utc>| t.with_timezone(&chrono::Local).format("%a %H:%M").to_string();
            for d in people {
                let line = match (d.online, d.presence.last()) {
                    (true, Some(s)) => format!("{} home since {}", paint.green("●"), local(s.from)),
                    (true, None) => format!("{} home", paint.green("●")),
                    (false, _) => {
                        format!("{} away, last seen {}", paint.dim("○"), d.last_seen.map(local).unwrap_or_default())
                    }
                };
                println!("  {:<24} {line}", d.display_name());
            }
            println!("\n  {}", paint.dim(&format!("As of the last scan, {}.", local(view.finished_at))));
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
        #[cfg(not(feature = "tls"))]
        Command::UpdateVendors => {
            bail!("this build of NattoWok can't download updates (built without the `tls` feature)")
        }
        #[cfg(feature = "tls")]
        Command::UpdateVendors => {
            use nattowok::oui;
            let before = oui::source();
            eprintln!("Downloading the IEEE manufacturer registry…");
            let csv = nattowok::fetch::get("https://standards-oui.ieee.org/oui/oui.csv", 20_000_000).await?;
            let rows = oui::parse_ieee_csv(&String::from_utf8_lossy(&csv));
            // A partial or garbled download must never replace a good list.
            anyhow::ensure!(
                rows.len() > 20_000,
                "the download looks incomplete ({} vendors); keeping the current list",
                rows.len()
            );
            std::fs::create_dir_all(&data_dir)?;
            let path = data_dir.join(oui::UPDATED_FILE);
            let tmp = path.with_extension("gz.tmp");
            std::fs::write(&tmp, oui::encode_table(&rows)?)?;
            std::fs::rename(&tmp, &path)?;
            println!("Updated: {} manufacturers (was: {before}). Saved to {}", rows.len(), path.display());
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
            row("Vendor list", nattowok::oui::source());
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

fn print_devices(paint: &Paint, devices: &[Device], network_findings: &[nattowok::model::Finding]) {
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
        let issues = d
            .findings
            .iter()
            .chain(network_findings.iter().filter(|f| f.device_id.as_deref() == Some(d.id.as_str())))
            .filter(|f| !f.ignored && f.severity > Severity::Info)
            .count();
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

fn print_exposure(paint: &Paint, report: &ScanReport) {
    let Some(exp) = &report.exposure else {
        println!(
            "\n  {} {}",
            paint.bold("Open to the internet"),
            paint.dim("(router doesn't share its port-forwarding list; UPnP is probably off)")
        );
        return;
    };
    let mappings: Vec<_> = exp.mappings.iter().filter(|m| m.enabled).collect();
    let address = exp.external_ip.as_deref().map(|ip| format!(" via {ip}")).unwrap_or_default();
    if mappings.is_empty() {
        println!("\n  {} {}{address}", paint.bold("Open to the internet"), paint.green("nothing"));
        return;
    }
    println!(
        "\n  {} {} port{}{address}",
        paint.bold("Open to the internet"),
        mappings.len(),
        if mappings.len() == 1 { "" } else { "s" }
    );
    for m in mappings {
        let who = m
            .internal_ip
            .map(|ip| {
                report.devices.iter().find(|d| d.ip == ip).map_or(ip.to_string(), |d| d.display_name().to_string())
            })
            .unwrap_or_else(|| "?".into());
        let by = m.description.as_deref().map(|d| paint.dim(&format!("  opened by \"{d}\""))).unwrap_or_default();
        println!("    {:>5}/{:<3} → {who}:{}{by}", m.external_port, m.protocol, m.internal_port);
    }
    if exp.shared_address {
        println!(
            "    {}",
            paint.dim("Your provider shares your public address, so these probably aren't reachable from outside.")
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
    print_devices(paint, &report.devices, &report.findings);
    print_exposure(paint, report);

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
        if let (Some(topic), Some(g)) = (f.topic, &report.router_guide)
            && let Some(step) = g.steps.get(&topic)
        {
            let on = if g.generic { "On your router".to_string() } else { format!("On your {}", g.brand) };
            println!("           {}", paint.dim(&format!("{on}: {step}")));
        }
    }
    for d in report.devices.iter().filter(|d| d.possible_match.is_some()) {
        let m = d.possible_match.as_ref().expect("filtered");
        println!(
            "\n  {} {} at {} looks like {} (offline): {}.",
            paint.blue("?"),
            d.display_name(),
            d.ip,
            paint.bold(&m.name),
            m.reasons.join(", ").to_lowercase()
        );
        println!("    If it is: nattowok merge {} {}", d.ip, m.id);
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

fn print_room_check(paint: &Paint, check: &room::RoomCheck) {
    use room::Verdict;
    let seen = check.devices.len();
    println!(
        "\n  {} {}",
        paint.bold(&format!("Room check on \"{}\"", check.network)),
        paint.dim(&format!("({seen} other device{} seen)", if seen == 1 { "" } else { "s" }))
    );
    let headline = &check.headline;
    let headline = if room::count(check, Verdict::Likely) > 0 {
        paint.red(headline)
    } else if room::count(check, Verdict::Unsure) > 0 || !check.hotspots.is_empty() || check.isolated {
        paint.yellow(headline)
    } else {
        paint.green(headline)
    };
    println!("  {}\n", paint.bold(&headline));
    if check.isolated {
        println!(
            "  {} No other devices are visible. Hotel and guest Wi-Fi often hide devices from each other,\n    so a camera on it wouldn't show up either. Rely on the checks below.\n",
            paint.yellow("!")
        );
    }
    let section = |title: &str, verdict: Verdict, mark: String| {
        let list: Vec<_> = check.devices.iter().filter(|d| d.verdict == verdict).collect();
        if list.is_empty() {
            return;
        }
        println!("  {}", paint.bold(title));
        for d in list {
            let vendor = d.vendor.as_deref().map(|v| format!("  {v}")).unwrap_or_default();
            println!("  {mark} {} {}{}", d.name, paint.dim(&format!("({})", d.ip)), paint.dim(&vendor));
            for r in &d.reasons {
                println!("      • {r}");
            }
        }
        println!();
    };
    section("Likely cameras", Verdict::Likely, paint.red("✗"));
    section("Find these and have a look", Verdict::Unsure, paint.yellow("!"));
    if !check.hotspots.is_empty() {
        println!("  {}", paint.bold("Wi-Fi networks named like a camera's own hotspot"));
        for h in &check.hotspots {
            let signal = h.signal_percent.map(|s| format!("  signal {s}%")).unwrap_or_default();
            println!("  {} {}{}", paint.yellow("!"), h.ssid, paint.dim(&signal));
        }
        println!("      • Cameras broadcast one while being set up, or to stream without the host's Wi-Fi.");
        println!("        A stronger signal means it's closer: walk around and run the check again.\n");
    }
    if !check.gone.is_empty() {
        println!("  {}", paint.bold("Gone since the last check (what you unplugged?)"));
        for d in &check.gone {
            println!("  {} {} {}", paint.blue("↓"), d.name, paint.dim(&format!("({})", d.ip)));
        }
        println!();
    }
    let fine: Vec<&str> =
        check.devices.iter().filter(|d| d.verdict == Verdict::Fine).map(|d| d.name.as_str()).collect();
    if !fine.is_empty() {
        println!("  {} {}\n", paint.green(&format!("Fine ({}):", fine.len())), fine.join(", "));
    }
    for n in &check.notes {
        println!("  {}", paint.dim(n));
    }
    println!("\n  {}", paint.bold("What this can't see"));
    for line in room::CANT_SEE {
        println!("  – {line}");
    }
    println!("\n  {}", paint.bold("Also check by hand"));
    for (i, (title, text)) in room::CHECKLIST.iter().enumerate() {
        println!("  {}. {}: {text}", i + 1, paint.bold(title));
    }
    println!("\n  {}", paint.dim("NattoWok only finds devices. It never logs in to them or opens their video."));
}
