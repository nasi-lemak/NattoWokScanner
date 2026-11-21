//! Rebuilds `data/flaws.json` from a downloaded copy of CISA's Known
//! Exploited Vulnerabilities catalog:
//! `cargo run --example build_flaws -- known_exploited_vulnerabilities.json`
fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("path to the downloaded catalog JSON");
    let catalog = nattowok::flaws::from_kev(&std::fs::read_to_string(path)?)?;
    std::fs::write("data/flaws.json", serde_json::to_string_pretty(&catalog)? + "\n")?;
    println!("{} entries from catalog {}", catalog.flaws.len(), catalog.version);
    Ok(())
}
