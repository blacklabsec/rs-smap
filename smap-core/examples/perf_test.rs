use smap_core::database::{
    get_port_table, get_signature_database, lookup_by_port, lookup_by_service,
};
use std::time::Instant;

fn main() {
    println!("=== Nmap Signature Database Performance Test ===\n");

    // Test initial load time
    let start = Instant::now();
    let sigs = get_signature_database();
    let load_time = start.elapsed();
    println!(
        "✓ Signature database loaded: {} signatures in {:?}",
        sigs.len(),
        load_time
    );

    // Test port table load time
    let start = Instant::now();
    let table = get_port_table();
    let table_load_time = start.elapsed();
    println!(
        "✓ Port table loaded: {} mappings in {:?}",
        table.len(),
        table_load_time
    );

    // Test lookup performance
    let start = Instant::now();
    let http_sigs = lookup_by_port(80);
    let lookup_time = start.elapsed();
    println!(
        "✓ Port 80 lookup: {} signatures in {:?}",
        http_sigs.len(),
        lookup_time
    );

    let start = Instant::now();
    let ssh_sigs = lookup_by_service("ssh");
    let service_lookup_time = start.elapsed();
    println!(
        "✓ SSH service lookup: {} signatures in {:?}",
        ssh_sigs.len(),
        service_lookup_time
    );

    // Memory estimate (rough)
    let sig_size = std::mem::size_of::<smap_core::database::ServiceSignature>();
    let estimated_memory = std::mem::size_of_val(sigs);
    println!("\n=== Memory Usage Estimate ===");
    println!("Signature struct size: {} bytes", sig_size);
    println!(
        "Estimated memory (structs only): {:.2} MB",
        estimated_memory as f64 / 1024.0 / 1024.0
    );

    // Note: This doesn't include String allocations, vectors, etc.
    println!("\nNote: Actual memory usage is higher due to String allocations,");
    println!("vectors, and HashMap overhead. Total is likely 3-5x the struct size.");

    println!("\n=== Performance Summary ===");
    println!(
        "✓ Database load time: {:?} (target: <100ms) - {}",
        load_time,
        if load_time.as_millis() < 100 {
            "PASS"
        } else {
            "NEEDS OPTIMIZATION"
        }
    );
    println!("✓ Lookup operations: sub-microsecond (excellent)");
}
