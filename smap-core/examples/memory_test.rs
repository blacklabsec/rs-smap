use smap_core::database::{get_port_table, get_signature_database};
use std::io::{self, BufRead};

fn main() {
    println!("Loading databases...");

    // Force initialization
    let sigs = get_signature_database();
    let table = get_port_table();

    println!("Loaded {} signatures", sigs.len());
    println!("Loaded {} port mappings", table.len());
    println!("\nPress Enter to check memory usage (use 'ps' or Activity Monitor)");
    println!("Process ID: {}", std::process::id());

    let stdin = io::stdin();
    let _ = stdin.lock().lines().next();

    println!("Done!");
}
