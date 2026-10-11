//! Converts the IEEE MA-L registry CSV into the compact, gzipped table that is
//! embedded in the binary. (`nattowok update-vendors` does the same at run time.)
//!
//! ```text
//! curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
//! cargo run --example build_oui -- oui.csv data/oui.tsv.gz
//! ```

use nattowok::oui;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: build_oui <oui.csv> <out.tsv.gz>");
    let rows = oui::parse_ieee_csv(&std::fs::read_to_string(&args[1])?);
    std::fs::write(&args[2], oui::encode_table(&rows)?)?;
    println!("wrote {} vendors to {}", rows.len(), args[2]);
    Ok(())
}
