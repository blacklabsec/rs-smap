use smap_core::correlation::correlate;
use smap_core::database::get_signature_database;

fn main() {
    // Test SSH correlation
    let ports = vec![22];
    let cpes = vec!["cpe:/a:openbsd:openssh:7.4".to_string()];

    println!("Testing with ports: {:?}", ports);
    println!("Testing with CPEs: {:?}", cpes);
    println!();

    // Check database for SSH signatures
    let db = get_signature_database();
    let ssh_sigs: Vec<_> = db
        .iter()
        .filter(|s| s.service == "ssh" && s.cpes.iter().any(|c| c.starts_with("cpe:/a:")))
        .take(3)
        .collect();

    println!("Sample SSH signatures in database:");
    for sig in &ssh_sigs {
        println!(
            "  Service: {}, CPEs: {:?}, Softmatch: {}, Heuristic: {:?}, Ports: {:?}",
            sig.service, sig.cpes, sig.softmatch, sig.heuristic, sig.ports
        );
    }
    println!();

    let (result, os) = correlate(&ports, &cpes);

    println!("Correlation results:");
    for port_info in &result {
        println!(
            "  Port {}: service='{}', version='{}', product='{}', protocol='{}', ssl={}, cpes={:?}",
            port_info.port,
            port_info.service,
            port_info.version,
            port_info.product,
            port_info.protocol,
            port_info.ssl,
            port_info.cpes
        );
    }
    println!();
    println!(
        "OS: name='{}', port={}, cpes={:?}",
        os.name, os.port, os.cpes
    );
}
