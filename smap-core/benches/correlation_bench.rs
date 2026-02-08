use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use smap_core::correlation::correlate;
use std::hint::black_box;

fn benchmark_correlation_small(c: &mut Criterion) {
    let ports = vec![22, 80, 443];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
    ];

    c.bench_function("correlate_small_3_ports", |b| {
        b.iter(|| correlate(black_box(&ports), black_box(&cpes)))
    });
}

fn benchmark_correlation_medium(c: &mut Criterion) {
    let ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080,
        8443, 9200,
    ];
    let cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:mysql:mysql:5.7.0".to_string(),
        "cpe:/a:postgresql:postgresql:9.6".to_string(),
        "cpe:/a:nginx:nginx:1.14.0".to_string(),
        "cpe:/o:canonical:ubuntu_linux:16.04".to_string(),
    ];

    c.bench_function("correlate_medium_20_ports", |b| {
        b.iter(|| correlate(black_box(&ports), black_box(&cpes)))
    });
}

fn benchmark_correlation_large(c: &mut Criterion) {
    let ports: Vec<u16> = (1..=100).collect();
    let mut cpes = vec![
        "cpe:/a:openbsd:openssh:7.4".to_string(),
        "cpe:/a:apache:http_server:2.4.6".to_string(),
        "cpe:/a:mysql:mysql:5.7.0".to_string(),
        "cpe:/a:postgresql:postgresql:9.6".to_string(),
        "cpe:/a:nginx:nginx:1.14.0".to_string(),
        "cpe:/a:microsoft:iis:10.0".to_string(),
        "cpe:/a:redis:redis:5.0.0".to_string(),
        "cpe:/a:mongodb:mongodb:4.0".to_string(),
        "cpe:/o:canonical:ubuntu_linux:18.04".to_string(),
        "cpe:/o:microsoft:windows_server_2016".to_string(),
    ];

    // Add more CPEs for realism
    for i in 0..15 {
        cpes.push(format!("cpe:/a:vendor{}:product{}:1.0.{}", i, i, i));
    }

    c.bench_function("correlate_large_100_ports", |b| {
        b.iter(|| correlate(black_box(&ports), black_box(&cpes)))
    });
}

fn benchmark_correlation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_scaling");

    for size in [5, 10, 25, 50, 100].iter() {
        let ports: Vec<u16> = (1..=*size).collect();
        let cpes = vec![
            "cpe:/a:openbsd:openssh:7.4".to_string(),
            "cpe:/a:apache:http_server:2.4.6".to_string(),
            "cpe:/a:mysql:mysql:5.7.0".to_string(),
        ];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| correlate(black_box(&ports), black_box(&cpes)))
        });
    }

    group.finish();
}

fn benchmark_correlation_many_cpes(c: &mut Criterion) {
    let ports = vec![22, 80, 443, 3306, 5432, 6379, 27017, 8080];
    let mut cpes = Vec::new();

    // Generate 50 CPEs
    for i in 0..50 {
        cpes.push(format!(
            "cpe:/a:vendor{}:product{}:{}.0.0",
            i % 10,
            i % 20,
            i % 5
        ));
    }

    c.bench_function("correlate_many_cpes_50", |b| {
        b.iter(|| correlate(black_box(&ports), black_box(&cpes)))
    });
}

criterion_group!(
    benches,
    benchmark_correlation_small,
    benchmark_correlation_medium,
    benchmark_correlation_large,
    benchmark_correlation_scaling,
    benchmark_correlation_many_cpes
);
criterion_main!(benches);
