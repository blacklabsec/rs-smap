use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use smap_core::database::{
    get_port_table, get_signature_database, lookup_by_cpe, lookup_by_port, lookup_by_service,
    signature_count,
};
use std::hint::black_box;

fn bench_initial_load(c: &mut Criterion) {
    c.bench_function("database_initial_load", |b| {
        b.iter(|| {
            let sigs = black_box(get_signature_database());
            black_box(sigs.len())
        })
    });
}

fn bench_port_table_load(c: &mut Criterion) {
    c.bench_function("port_table_load", |b| {
        b.iter(|| {
            let table = black_box(get_port_table());
            black_box(table.len())
        })
    });
}

fn bench_signature_count(c: &mut Criterion) {
    c.bench_function("signature_count", |b| {
        b.iter(|| black_box(signature_count()))
    });
}

fn bench_port_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_lookup");

    // Common ports
    for port in [22, 80, 443, 3306, 5432, 8080, 27017] {
        group.bench_with_input(BenchmarkId::from_parameter(port), &port, |b, &port| {
            b.iter(|| {
                let sigs = black_box(lookup_by_port(port));
                black_box(sigs.len())
            })
        });
    }

    group.finish();
}

fn bench_service_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("service_lookup");

    let services = [
        "http",
        "ssh",
        "ftp",
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
    ];

    for service in services {
        group.bench_with_input(
            BenchmarkId::from_parameter(service),
            &service,
            |b, &service| {
                b.iter(|| {
                    let sigs = black_box(lookup_by_service(service));
                    black_box(sigs.len())
                })
            },
        );
    }

    group.finish();
}

fn bench_cpe_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpe_lookup");

    let cpes = ["apache", "microsoft", "nginx", "openssh"];

    for cpe in cpes {
        group.bench_with_input(BenchmarkId::from_parameter(cpe), &cpe, |b, &cpe| {
            b.iter(|| {
                let sigs = black_box(lookup_by_cpe(cpe));
                black_box(sigs.len())
            })
        });
    }

    group.finish();
}

fn bench_port_table_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_table_lookup");

    for port in [22, 80, 443, 3306] {
        group.bench_with_input(BenchmarkId::from_parameter(port), &port, |b, &port| {
            b.iter(|| {
                let table = get_port_table();
                black_box(table.get(&port))
            })
        });
    }

    group.finish();
}

fn bench_concurrent_access(c: &mut Criterion) {
    c.bench_function("concurrent_signature_access", |b| {
        b.iter(|| {
            // Simulate concurrent access patterns
            let sigs = get_signature_database();
            let table = get_port_table();

            let http = lookup_by_port(80);
            let ssh_sigs = lookup_by_service("ssh");
            let apache = lookup_by_cpe("apache");

            black_box((
                sigs.len(),
                table.len(),
                http.len(),
                ssh_sigs.len(),
                apache.len(),
            ))
        })
    });
}

criterion_group!(
    benches,
    bench_initial_load,
    bench_port_table_load,
    bench_signature_count,
    bench_port_lookup,
    bench_service_lookup,
    bench_cpe_lookup,
    bench_port_table_lookup,
    bench_concurrent_access
);

criterion_main!(benches);
