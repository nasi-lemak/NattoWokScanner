//! "Are you getting what you pay for?" Compares speed tests with the plan
//! speed you pay for, by time of day, and decides when scheduled tests run
//! so every part of the day gets measured.

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeDelta, Timelike, Utc};
use serde::Serialize;

use crate::speedtest::SpeedResult;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Window {
    Morning,
    Afternoon,
    Evening,
    Night,
}

impl Window {
    pub const ALL: [Window; 4] = [Window::Morning, Window::Afternoon, Window::Evening, Window::Night];

    pub fn label(self) -> &'static str {
        match self {
            Window::Morning => "Mornings (6–12)",
            Window::Afternoon => "Afternoons (12–18)",
            Window::Evening => "Evenings (18–23)",
            Window::Night => "Nights (23–6)",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Window::Morning => "mornings",
            Window::Afternoon => "afternoons",
            Window::Evening => "evenings",
            Window::Night => "nights",
        }
    }

    /// Start hour and length in hours.
    fn span(self) -> (u32, u32) {
        match self {
            Window::Morning => (6, 6),
            Window::Afternoon => (12, 6),
            Window::Evening => (18, 5),
            Window::Night => (23, 7),
        }
    }

    pub fn of_hour(hour: u32) -> Window {
        match hour {
            6..=11 => Window::Morning,
            12..=17 => Window::Afternoon,
            18..=22 => Window::Evening,
            _ => Window::Night,
        }
    }
}

/// The window a local time falls in, and the date that window started on
/// (a night starting at 23:00 belongs to that evening's date).
fn window_of(t: DateTime<Local>) -> (Window, NaiveDate) {
    let w = Window::of_hour(t.hour());
    let date = if w == Window::Night && t.hour() < 6 { t.date_naive() - TimeDelta::days(1) } else { t.date_naive() };
    (w, date)
}

/// Which windows get a scheduled test on a given day: evenings (the busy
/// time) whenever possible, the others in rotation.
pub fn windows_for_day(per_day: u8, date: NaiveDate) -> Vec<Window> {
    let d = date.num_days_from_ce().unsigned_abs() as usize;
    match per_day {
        0 => vec![],
        1 => vec![Window::ALL[d % 4]],
        2 | 3 => vec![Window::Evening, [Window::Morning, Window::Afternoon, Window::Night][d % 3]],
        _ => Window::ALL.to_vec(),
    }
}

/// Minutes into the window a test starts: spread out and different each
/// day, so results aren't all from the same minute.
fn offset_minutes(w: Window, date: NaiveDate) -> u32 {
    let (_, hours) = w.span();
    let seed = date.num_days_from_ce().unsigned_abs().wrapping_mul(2_654_435_761) ^ (w as u32).wrapping_mul(40_503);
    seed % (hours * 60 - 30)
}

/// Whether a scheduled test should run now, given the tests already done.
pub fn due(now: DateTime<Utc>, per_day: u8, history: &[SpeedResult]) -> bool {
    let local = now.with_timezone(&Local);
    let (w, date) = window_of(local);
    if !windows_for_day(per_day, date).contains(&w) {
        return false;
    }
    let (start_hour, _) = w.span();
    let start = date.and_hms_opt(start_hour, 0, 0).and_then(|t| t.and_local_timezone(Local).earliest());
    let Some(start) = start else { return false };
    let minutes_in = (local - start).num_minutes();
    if minutes_in < i64::from(offset_minutes(w, date)) {
        return false;
    }
    // Already tested in this window today (by hand or on schedule)?
    !history.iter().any(|r| window_of(r.at.with_timezone(&Local)) == (w, date))
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct WindowStats {
    pub window: Window,
    pub label: &'static str,
    pub tests: usize,
    pub median_down: f64,
    pub median_up: f64,
    /// Percent of the plan's download (and upload, when known).
    pub down_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_pct: Option<f64>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Comparison {
    pub days: i64,
    pub plan_down: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_up: Option<f64>,
    pub tests: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_down_pct: Option<f64>,
    pub windows: Vec<WindowStats>,
    pub headline: String,
    pub notes: Vec<String>,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2],
        n => (v[n / 2 - 1] + v[n / 2]) / 2.0,
    }
}

fn pct(x: f64, of: f64) -> f64 {
    (100.0 * x / of).round()
}

pub fn compare(
    history: &[&SpeedResult],
    plan_down: f64,
    plan_up: Option<f64>,
    days: i64,
    now: DateTime<Utc>,
) -> Comparison {
    let since = now - TimeDelta::days(days);
    let recent: Vec<&SpeedResult> = history.iter().copied().filter(|r| r.at >= since).collect();
    let mut windows = Vec::new();
    for w in Window::ALL {
        let in_w: Vec<&SpeedResult> =
            recent.iter().copied().filter(|r| Window::of_hour(r.at.with_timezone(&Local).hour()) == w).collect();
        if in_w.is_empty() {
            continue;
        }
        let down = median(in_w.iter().map(|r| r.download_mbps).collect());
        let up = median(in_w.iter().map(|r| r.upload_mbps).collect());
        windows.push(WindowStats {
            window: w,
            label: w.label(),
            tests: in_w.len(),
            median_down: (down * 10.0).round() / 10.0,
            median_up: (up * 10.0).round() / 10.0,
            down_pct: pct(down, plan_down),
            up_pct: plan_up.map(|p| pct(up, p)),
        });
    }
    let overall_down_pct =
        (!recent.is_empty()).then(|| pct(median(recent.iter().map(|r| r.download_mbps).collect()), plan_down));
    let mut notes = Vec::new();
    let headline = match overall_down_pct {
        None => format!("No speed tests in the last {days} days yet"),
        Some(all) => {
            let worst = windows.iter().filter(|w| w.tests >= 2).min_by(|a, b| a.down_pct.total_cmp(&b.down_pct));
            let best = windows.iter().max_by(|a, b| a.down_pct.total_cmp(&b.down_pct));
            match (worst, best) {
                (Some(w), Some(b)) if w.down_pct < 80.0 && b.down_pct - w.down_pct >= 15.0 => format!(
                    "{} average {}% of your plan's download speed ({} tests); {} {}%",
                    capitalize(w.window.short()),
                    w.down_pct,
                    w.tests,
                    b.window.short(),
                    b.down_pct
                ),
                _ if all >= 80.0 => format!("You're getting what you pay for: {all}% of your plan's download speed"),
                _ => format!("{all}% of your plan's download speed, at all times of day"),
            }
        }
    };
    if let Some(all) = overall_down_pct {
        let wifi = recent.iter().filter(|r| r.wifi == Some(true)).count();
        if wifi * 2 > recent.len() && all < 80.0 {
            notes.push(
                "Most of these tests ran over Wi-Fi, which on its own can be slower than your plan. For numbers to show your provider, test on a cable or right next to the router.".into(),
            );
        }
        if windows.iter().any(|w| w.window == Window::Evening && w.tests >= 2 && w.down_pct < 50.0)
            && windows.iter().any(|w| w.window != Window::Evening && w.down_pct >= 75.0)
        {
            notes.push(
                "Speeds that drop in the evening but not at other times usually mean your provider's network is congested at busy times. That's worth raising with them, with these results.".into(),
            );
        }
        let missing: Vec<&str> =
            Window::ALL.iter().filter(|w| !windows.iter().any(|s| s.window == **w)).map(|w| w.short()).collect();
        if !missing.is_empty() && recent.len() >= 3 {
            notes.push(format!("No tests yet from {}: scheduled tests fill those in.", missing.join(" or ")));
        }
    }
    Comparison { days, plan_down, plan_up, tests: recent.len(), overall_down_pct, windows, headline, notes }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// "500" or "500/50" (download/upload Mbps).
pub fn parse_plan(text: &str) -> Option<(f64, Option<f64>)> {
    let (down, up) = match text.split_once('/') {
        Some((d, u)) => (d, Some(u)),
        None => (text, None),
    };
    let num = |s: &str| s.trim().trim_end_matches("Mbps").trim().parse::<f64>().ok().filter(|v| *v > 0.0);
    let down = num(down)?;
    match up {
        Some(u) => Some((down, Some(num(u)?))),
        None => Some((down, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::speedtest::Grade;

    fn result(at: DateTime<Utc>, down: f64) -> SpeedResult {
        SpeedResult {
            at,
            location: None,
            download_mbps: down,
            upload_mbps: down / 10.0,
            idle_ms: 10.0,
            loaded_down_ms: 20.0,
            loaded_up_ms: 20.0,
            grade: Grade::A,
            data_used_mb: 300.0,
            verdict: String::new(),
            advice: None,
            scheduled: true,
            wifi: Some(false),
            network: None,
        }
    }

    fn local(day: u32, hour: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2026, 11, day)
            .unwrap()
            .and_hms_opt(hour, 30, 0)
            .unwrap()
            .and_local_timezone(Local)
            .earliest()
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn finds_slow_evenings() {
        let now = local(20, 12);
        let mut h = Vec::new();
        for day in 10..18 {
            h.push(result(local(day, 9), 480.0));
            h.push(result(local(day, 20), 190.0));
        }
        let refs: Vec<&SpeedResult> = h.iter().collect();
        let c = compare(&refs, 500.0, Some(50.0), 30, now);
        assert_eq!(c.tests, 16);
        assert_eq!(c.headline, "Evenings average 38% of your plan's download speed (8 tests); mornings 96%");
        assert!(c.notes.iter().any(|n| n.contains("congested at busy times")), "{:?}", c.notes);
        let evening = c.windows.iter().find(|w| w.window == Window::Evening).unwrap();
        assert_eq!(evening.up_pct, Some(38.0));
    }

    #[test]
    fn says_when_its_fine() {
        let h = [result(local(18, 9), 470.0), result(local(18, 20), 460.0)];
        let refs: Vec<&SpeedResult> = h.iter().collect();
        let c = compare(&refs, 500.0, None, 30, local(20, 12));
        assert!(c.headline.starts_with("You're getting what you pay for: 93%"), "{}", c.headline);
        assert_eq!(compare(&[], 500.0, None, 30, local(20, 12)).headline, "No speed tests in the last 30 days yet");
    }

    #[test]
    fn schedules_each_window_once() {
        let date = NaiveDate::from_ymd_opt(2026, 11, 20).unwrap();
        assert_eq!(windows_for_day(4, date).len(), 4);
        assert!(windows_for_day(2, date).contains(&Window::Evening));
        assert_eq!(windows_for_day(0, date), vec![]);
        // Over four days, once a day covers every window.
        let mut seen: Vec<Window> = (0..4).flat_map(|i| windows_for_day(1, date + TimeDelta::days(i))).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 4);

        // At the very end of the evening window the test is due, and once done, it isn't.
        let late = local(20, 22) + TimeDelta::minutes(29);
        assert!(due(late, 4, &[]));
        assert!(!due(late, 4, &[result(local(20, 19), 100.0)]));
        assert!(!due(late, 0, &[]));
        // A night test at 02:00 counts for the night that began the evening before.
        let night = local(21, 5);
        assert!(!due(night, 4, &[result(local(20, 23), 100.0)]));
    }

    #[test]
    fn parses_plans() {
        assert_eq!(parse_plan("500"), Some((500.0, None)));
        assert_eq!(parse_plan("500/50"), Some((500.0, Some(50.0))));
        assert_eq!(parse_plan("100 Mbps / 20 Mbps"), Some((100.0, Some(20.0))));
        assert_eq!(parse_plan("fast"), None);
        assert_eq!(parse_plan("0"), None);
    }
}
