//! Converts the IEEE MA-L registry CSV into the compact, gzipped table that is
//! embedded in the binary.
//!
//! ```text
//! curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
//! cargo run --example build_oui -- oui.csv data/oui.tsv.gz
//! ```

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: build_oui <oui.csv> <out.tsv.gz>");
    let text = std::fs::read_to_string(&args[1])?;

    let mut rows: Vec<(String, String)> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = split_csv(line);
            let prefix = fields.get(1)?.trim().to_ascii_uppercase();
            let name = tidy(fields.get(2)?);
            (prefix.len() == 6 && !name.is_empty()).then_some((prefix, name))
        })
        .collect();
    rows.sort();
    rows.dedup_by(|a, b| a.0 == b.0);

    let mut out = GzEncoder::new(std::fs::File::create(&args[2])?, Compression::best());
    for (prefix, name) in &rows {
        writeln!(out, "{prefix}\t{name}")?;
    }
    out.finish()?;
    println!("wrote {} vendors to {}", rows.len(), args[2]);
    Ok(())
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                fields.last_mut().unwrap().push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(String::new()),
            _ => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

/// Strips legal-entity noise so people see "Apple" rather than "Apple, Inc.".
fn tidy(name: &str) -> String {
    const SUFFIXES: &[&str] = &[
        "co., ltd.",
        "co.,ltd.",
        "co., ltd",
        "co.,ltd",
        "co. ltd.",
        "co ltd",
        "corporation",
        "corp.",
        "corp",
        "incorporated",
        "inc.",
        "inc",
        "limited",
        "ltd.",
        "ltd",
        "llc",
        "l.l.c.",
        "gmbh",
        "s.a.",
        "s.p.a.",
        "b.v.",
        "pty",
        "a/s",
        "ab",
        "oy",
        "sas",
        "s.r.l.",
        "srl",
        "technology",
        "technologies",
        "electronics",
        "co.",
        "co",
    ];
    let mut s = name.split_whitespace().collect::<Vec<_>>().join(" ");
    loop {
        let trimmed = s.trim_end_matches([',', ' ', '.']).to_string();
        let lower = trimmed.to_ascii_lowercase();
        let Some(suffix) = SUFFIXES.iter().find(|suf| {
            lower.ends_with(*suf) && lower.len() > suf.len() + 2 && {
                let boundary = lower.as_bytes()[lower.len() - suf.len() - 1];
                boundary == b' ' || boundary == b','
            }
        }) else {
            return trimmed;
        };
        s = trimmed[..trimmed.len() - suffix.len()].to_string();
    }
}
