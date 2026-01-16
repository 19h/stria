//! Filter matching benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn filter_benchmarks(_c: &mut Criterion) {
    // Placeholder for filter benchmarks
    // TODO: Add benchmarks for:
    // - Domain matching
    // - Regex matching
    // - Blocklist lookups
    // - Rule evaluation
}

criterion_group!(benches, filter_benchmarks);
criterion_main!(benches);
