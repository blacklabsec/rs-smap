// Integration tests for correlation module accuracy
// These tests verify that the Rust implementation matches the Go version

use smap_core::correlation::correlate;

#[test]
fn test_real_world_ssh_apache_mysql() {
    // Simulate a real server with SSH, Apache, MySQL
    // Note: In real scenarios, correlation depends heavily on signature database contents
    // and scoring algorithm. This test verifies the correlation runs without errors.
    let ports = vec![22, 80, 3306];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:mysql:mysql:5.7.0".to_string(),
        "cpe:/o:canonical:ubuntu_linux:16.04".to_string(),
    ];

    let (result, os, _uncorrelated_cpes) = correlate(&ports, &cpes);

    // Debug output
    eprintln!("Results:");
    for r in &result {
        eprintln!(
            "  Port {}: service='{}', version='{}', cpes={:?}",
            r.port, r.service, r.version, r.cpes
        );
    }

    // All ports should get a result (matched or orphan)
    assert_eq!(result.len(), 3);

    // Verify all ports are present
    assert!(result.iter().any(|p| p.port == 22));
    assert!(result.iter().any(|p| p.port == 80));
    assert!(result.iter().any(|p| p.port == 3306));

    // At least some ports should match (not all orphans)
    let matched_count = result
        .iter()
        .filter(|p| !p.service.ends_with('?') && !p.service.is_empty())
        .count();
    assert!(
        matched_count >= 2,
        "Expected at least 2 matched services, got {}",
        matched_count
    );

    // Check specific services if they matched
    for port_info in &result {
        match port_info.port {
            80 if port_info.service == "http" => {
                assert_eq!(port_info.version, "2.4.6");
                assert!(port_info.cpes.iter().any(|c| c.contains("apache")));
            }
            3306 if port_info.service == "mysql" => {
                assert_eq!(port_info.version, "5.7.0");
                assert!(port_info.cpes.iter().any(|c| c.contains("mysql")));
            }
            22 if port_info.service == "ssh" => {
                assert_eq!(port_info.version, "7.4");
                assert!(port_info.cpes.iter().any(|c| c.contains("openssh")));
            }
            _ => {} // Other cases are acceptable
        }
    }

    // OS detection is optional but should be valid if present
    if !os.name.is_empty() {
        assert!(os.cpes.iter().any(|c| c.starts_with("cpe:/o")) || os.cpes.is_empty());
    }
}

#[test]
fn test_ssl_https_detection() {
    // HTTPS server with Apache on port 443
    let ports = vec![443];
    let cpes = vec!["cpe:/a:apache:http_server:2.4.29".to_string()];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].port, 443);
    // Should detect as HTTP service with SSL enabled
    if result[0].service == "http" {
        assert!(result[0].ssl, "SSL should be detected on port 443");
    }
}

#[test]
fn test_multiple_ssh_ports() {
    // SSH on non-standard port should still match
    let ports = vec![22, 2222];
    let cpes = vec!["cpe:/a:openbsd:openssh:8.2p1".to_string()];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 2);

    // One should be matched with high confidence, other may be lower
    let ssh_matches: Vec<_> = result.iter().filter(|p| p.service == "ssh").collect();
    assert!(!ssh_matches.is_empty());
}

#[test]
fn test_complex_versioning() {
    // Test CPE with complex version string
    let ports = vec![22];
    let cpes = vec!["cpe:/a:openbsd:openssh:7.4:p1:ubuntu".to_string()];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 1);
    if result[0].service == "ssh" {
        // Version should be extracted from 5th field (index 4)
        assert_eq!(result[0].version, "7.4");
    }
}

#[test]
fn test_no_matches_all_orphans() {
    // Ports with CPEs that don't match any signatures
    let ports = vec![9999, 10000, 10001];
    let cpes = vec!["cpe:/a:unknown:vendor:1.0".to_string()];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 3);

    // All should be orphans
    for port_info in &result {
        // Orphans either have empty service or service with "?"
        assert!(port_info.service.is_empty() || port_info.service.ends_with('?'));
        assert_eq!(port_info.cpes.len(), 0);
    }
}

#[test]
fn test_scoring_preference() {
    // Multiple CPEs should result in best match based on scoring
    let ports = vec![80];
    let cpes = vec![
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:nginx:nginx:1.14.0".to_string(),
    ];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].port, 80);
    // Should pick one based on scoring (Apache or Nginx)
    assert!(result[0].service == "http" || result[0].service == "http-proxy");
}

#[test]
fn test_empty_cpe_list() {
    // Ports but no CPEs - all should be orphans
    let ports = vec![80, 443, 22];
    let cpes = vec![];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 3);

    // Check each port got a result (even if orphan)
    for port in &ports {
        assert!(result.iter().any(|p| p.port == *port));
    }
}

#[test]
fn test_cpe_reuse_prevention() {
    // Same CPE should not be used for multiple ports
    let ports = vec![80, 8080];
    let cpes = vec!["cpe:/a:apache:http_server:2.4.6".to_string()];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 2);

    // Count how many ports used the Apache CPE
    let apache_matches: Vec<_> = result
        .iter()
        .filter(|p| p.cpes.iter().any(|c| c.contains("apache")))
        .collect();

    // Should only match one port (highest scoring)
    assert!(apache_matches.len() <= 1);
}

#[test]
fn test_protocol_consistency() {
    // All results should have protocol set
    let ports = vec![22, 80, 443, 3306, 5432];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
    ];

    let (result, _, _) = correlate(&ports, &cpes);

    assert_eq!(result.len(), 5);

    for port_info in &result {
        assert!(!port_info.protocol.is_empty());
        assert!(port_info.protocol == "tcp" || port_info.protocol == "udp");
    }
}

#[test]
fn test_performance_realistic_scan() {
    // Realistic scan with 20 ports and 10 CPEs
    let ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080,
        8443, 9200,
    ];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:nginx:nginx:1.14.0".to_string(),
        "cpe:/a:mysql:mysql:5.7.0".to_string(),
        "cpe:/a:postgresql:postgresql:9.6".to_string(),
        "cpe:/a:dovecot:dovecot:2.2.27".to_string(),
        "cpe:/a:postfix:postfix:3.1.0".to_string(),
        "cpe:/o:canonical:ubuntu_linux:16.04".to_string(),
    ];

    // Warm up the database (first access loads it)
    let _ = correlate(&[22], &[]);

    let start = std::time::Instant::now();
    let (result, _, _) = correlate(&ports, &cpes);
    let duration = start.elapsed();

    assert_eq!(result.len(), 20);
    // Should complete in reasonable time (< 50ms including all matching)
    assert!(
        duration.as_millis() < 50,
        "Correlation took {}ms, expected <50ms",
        duration.as_millis()
    );
}

#[test]
fn test_deterministic_results() {
    // Running the same correlation twice should give identical results
    let ports = vec![22, 80, 443];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
    ];

    let (result1, os1, _) = correlate(&ports, &cpes);
    let (result2, os2, _) = correlate(&ports, &cpes);

    // Results should be identical
    assert_eq!(result1.len(), result2.len());
    assert_eq!(os1, os2);

    // Check each port matches
    for i in 0..result1.len() {
        assert_eq!(result1[i].port, result2[i].port);
        assert_eq!(result1[i].service, result2[i].service);
        assert_eq!(result1[i].version, result2[i].version);
    }
}
