use smap_core::correlation::correlate;

fn main() {
    // Exact test case from integration test
    let ports = vec![22, 80, 3306];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:mysql:mysql:5.7.0".to_string(),
        "cpe:/o:canonical:ubuntu_linux:16.04".to_string(),
    ];

    println!("Testing with ports: {:?}", ports);
    println!("Testing with CPEs:");
    for cpe in &cpes {
        println!("  {}", cpe);
    }
    println!();

    let (result, os) = correlate(&ports, &cpes);

    println!("Results:");
    for r in &result {
        println!(
            "  Port {}: service='{}', version='{}', product='{}', cpes={:?}",
            r.port, r.service, r.version, r.product, r.cpes
        );
    }
    println!();
    println!(
        "OS: name='{}', port={}, cpes={:?}",
        os.name, os.port, os.cpes
    );
}
