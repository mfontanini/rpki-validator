use std::time::Duration;

use prometheus::{HistogramOpts, HistogramVec, IntGaugeVec, Opts, Registry};

#[derive(Clone)]
pub struct Metrics {
    update_time: HistogramVec,
    total_records: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> Self {
        let update_time_buckets = vec![
            1.0, 2.0, 3.0, 5.0, 7.5, 10.0, 15.0, 20.0, 40.0, 60.0, 80.0, 120.0, 160.0, 200.0
        ];

        let update_time = HistogramVec::new(
            HistogramOpts::new(
                "update_time_duration_seconds",
                "Time taken to update and process every trust anchor",
            ).buckets(update_time_buckets),
            &["trust_anchor"]
        ).unwrap();

        let total_records = IntGaugeVec::new(
            Opts::new(
                "records_total",
                "Number of records in storage",
            ),
            &["trust_anchor"],
        ).unwrap();

        Metrics {
            update_time,
            total_records,
        }
    }

    pub fn register(&self, registry: &mut Registry) {
        registry
            .register(Box::new(self.update_time.clone()))
            .unwrap();
        registry
            .register(Box::new(self.total_records.clone()))
            .unwrap();
    }

    pub fn observe_update_time(&mut self, trust_anchor: &str, elapsed: Duration) {
        // Convert to seconds
        let elapsed = elapsed.as_secs() as f64 + elapsed.subsec_millis() as f64 * 0.001;
        self.update_time
            .with_label_values(&[&trust_anchor])
            .observe(elapsed);
    }

    pub fn set_total_records(&mut self, trust_anchor: &str, record_count: i64) {
        // Convert to seconds
        self.total_records
            .with_label_values(&[&trust_anchor])
            .set(record_count);
    }
}
