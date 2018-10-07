#[macro_use] extern crate bencher;
extern crate ipnetwork;
extern crate rpki_validator;
extern crate rpki;

use std::net::IpAddr;
use std::path::PathBuf;

use bencher::Bencher;

use ipnetwork::IpNetwork;

use rpki::asres::AsId;

use rpki_validator::storage::{RecordStorage, Record};

fn bench_lookup_ipv4(b: &mut Bencher) {
    let mut storage = RecordStorage::new();
    let mut current_buffer : [u8; 4] = [1, 0, 0, 0];
    let origins = vec![
        AsId::from(1),
        AsId::from(2),
        AsId::from(3),
    ];
    let total_prefixes = 10000;
    for _ in 0..total_prefixes {
        let addr = IpAddr::from(current_buffer);
        let mut records = Vec::new();
        let prefix = IpNetwork::new(addr, 24).unwrap();
        for origin in origins.iter() {
            records.push(Record::new(prefix, *origin, 24));
        }
        // We need unique paths, otherwise we'll keep erasing the previous records
        // thinking the source file was modified
        storage.add_records(records, PathBuf::from(format!("{:?}", prefix)));
        if current_buffer[2] == 255 {
            current_buffer[2] = 0;
            current_buffer[1] += 1;
        }
        else {
            current_buffer[2] += 1;
        }
    }
    assert_eq!(total_prefixes, storage.total_prefixes());

    let prefix = IpNetwork::V4("1.2.3.0/24".parse().unwrap());
    b.iter(|| {
        storage.find_records(&prefix)
    });
}

benchmark_group!(benches, bench_lookup_ipv4);
benchmark_main!(benches);
