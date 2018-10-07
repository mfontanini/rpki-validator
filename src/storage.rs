use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::path::PathBuf;

use ipnetwork::IpNetwork;

use rpki::asres::AsId;

#[derive(Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct TrustAnchor {
    name: String,
}

impl TrustAnchor {
    pub fn new(name: String) -> Self {
        TrustAnchor {
            name,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    prefix: IpNetwork,
    origin: AsId,
    max_length: u8,
}

impl Record {
    pub fn new(prefix: IpNetwork, origin: AsId, max_length: u8) -> Self {
        Record {
            prefix,
            origin,
            max_length,
        }
    }

    pub fn prefix(&self) -> &IpNetwork {
        &self.prefix
    }

    pub fn origin(&self) -> AsId {
        self.origin
    }

    pub fn max_length(&self) -> u8 {
        self.max_length
    }
}

// RecordMetadata

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct RecordMetadata {
    origin: AsId,
    max_length: u8,
    path: Arc<PathBuf>,
    trust_anchor: Arc<TrustAnchor>,
}

impl RecordMetadata {
    fn new(origin: AsId,
           max_length: u8,
           path: Arc<PathBuf>,
           trust_anchor: Arc<TrustAnchor>)
        -> Self
    {
        RecordMetadata {
            origin,
            max_length,
            path,
            trust_anchor,
        }
    }
}

pub struct RecordStorage {
    // Note: the record metadata entries for a given prefix is sorted
    // by (origin, max_length, path). This allows us to remove duplicates when iterating them
    prefix_records: HashMap<IpNetwork, Vec<RecordMetadata>>,
    known_paths: HashSet<Arc<PathBuf>>,
    trust_anchor_total_records: HashMap<Arc<TrustAnchor>, i64>,
}

impl RecordStorage {
    const MIN_IPV4_PREFIX_LENGTH : u8 = 8;
    const MIN_IPV6_PREFIX_LENGTH : u8 = 19;

    pub fn new() -> Self {
        RecordStorage {
            prefix_records: HashMap::new(),
            known_paths: HashSet::new(),
            trust_anchor_total_records: HashMap::new(),
        }
    }

    fn set_total_records_diff(&mut self, trust_anchor: Arc<TrustAnchor>, diff: i64) {
        *self.trust_anchor_total_records.entry(trust_anchor).or_insert(0) += diff;
    }

    pub fn add_records(&mut self,
                       records: Vec<Record>,
                       source_path: PathBuf,
                       trust_anchor: &Arc<TrustAnchor>) {
        let is_modified = self.known_paths.remove(&source_path);
        if is_modified {
            self.remove_records([ source_path.clone() ].iter());
        }
        // Increment the count for this TA
        self.set_total_records_diff(trust_anchor.clone(), records.len() as i64);

        let source_path = Arc::new(source_path);
        for record in records {
            let metadata = RecordMetadata::new(
                record.origin,
                record.max_length,
                source_path.clone(),
                trust_anchor.clone(),
            );
            let records = self.prefix_records.entry(record.prefix).or_default();
            records.push(metadata);
            records.sort();
        }
        self.known_paths.insert(source_path);
    }

    pub fn remove_records<'a>(&mut self, source_paths: impl Iterator<Item=&'a PathBuf>) {
        let mut trust_anchor_deletions : HashMap<Arc<TrustAnchor>, i64> = HashMap::new();
        let source_paths = source_paths.collect::<HashSet<_>>();
        let mut empty_prefixes = Vec::new();
        for (prefix, records) in self.prefix_records.iter_mut() {
            records.retain(|r| {
                let should_retain = !source_paths.contains(&*r.path);
                if !should_retain {
                    *trust_anchor_deletions.entry(r.trust_anchor.clone()).or_default() += 1;
                }
                should_retain
            });
            if records.is_empty() {
                empty_prefixes.push(prefix.clone());
            }
        }
        for prefix in empty_prefixes {
            self.prefix_records.remove(&prefix);
        }
        for (trust_anchor, removed) in trust_anchor_deletions {
            self.set_total_records_diff(trust_anchor, removed * -1);
        } 
    }

    pub fn find_records(&self, prefix: &IpNetwork) -> Vec<Record> {
        let (address, max_mask, min_mask) = match prefix.ip() {
            IpAddr::V4(a) => (u32::from(a) as u128, 32, Self::MIN_IPV4_PREFIX_LENGTH),
            IpAddr::V6(a) => (u128::from(a), 128, Self::MIN_IPV6_PREFIX_LENGTH),
        };
        let mut mask_length = prefix.prefix();
        let mut mask : u128 = (2u128.pow(mask_length as u32) - 1) << (max_mask - mask_length);
        let mut output = Vec::new();
        while mask_length >= min_mask {
            let current_address = address & mask;
            let current_address = if prefix.is_ipv6() {
                IpAddr::V6(Ipv6Addr::from(current_address))
            } else {
                IpAddr::V4(Ipv4Addr::from(current_address as u32))
            };
            let current_prefix = IpNetwork::new(current_address, mask_length).unwrap();
            if let Some(records) = self.prefix_records.get(&current_prefix) {
                let mut last_tuple = None;
                for record in records {
                    let current_tuple = (record.origin, record.max_length);
                    if last_tuple != Some(current_tuple) {
                        output.push(Record::new(current_prefix, record.origin, record.max_length));
                    }
                    last_tuple = Some(current_tuple);
                }
            }
            mask_length -= 1;
            mask = mask << 1;
        }
        output
    }

    pub fn total_prefixes(&self) -> usize {
        self.prefix_records.len()
    }

    pub fn total_records(&self, trust_anchor_name: &str) -> i64 {
        let trust_anchor = TrustAnchor::new(trust_anchor_name.to_string());
        *self.trust_anchor_total_records.get(&trust_anchor).unwrap_or(&0) 
    }

    pub fn records(&self) -> Vec<Record> {
        let mut output = Vec::new();
        for (prefix, metadatas) in self.prefix_records.iter() {
            let mut last_tuple = None;
            for metadata in metadatas {
                let current_tuple = (metadata.origin, metadata.max_length);
                // Make sure we don't push the same record twice
                if last_tuple != Some(current_tuple) {
                    output.push(Record::new(*prefix, metadata.origin, metadata.max_length));
                }
                last_tuple = Some(current_tuple);
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_records_ipv4() {
        let mut storage = RecordStorage::new();
        let records = vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 24),
            Record::new(IpNetwork::V4("3.3.3.0/24".parse().unwrap()), AsId::from(2), 23),
            Record::new(IpNetwork::V4("1.2.0.0/16".parse().unwrap()), AsId::from(3), 16),
        ];
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        storage.add_records(records.clone(), PathBuf::new(), &trust_anchor);
        assert_eq!(
            storage.find_records(&IpNetwork::V4("1.2.3.0/24".parse().unwrap())),
            [ records[0].clone(), records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V4("1.2.0.0/16".parse().unwrap())),
            [ records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V4("1.2.0.0/24".parse().unwrap())),
            [ records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V4("3.3.0.0/16".parse().unwrap())),
            []
        );

        assert_eq!(3, storage.total_records(trust_anchor.name()));
    }

    #[test]
    fn find_records_ipv6() {
        let mut storage = RecordStorage::new();
        let records = vec![
            Record::new(IpNetwork::V6("dead:beef::/32".parse().unwrap()), AsId::from(1), 24),
            Record::new(IpNetwork::V6("feed:beef::/32".parse().unwrap()), AsId::from(2), 23),
            Record::new(IpNetwork::V6("dead:be00::/24".parse().unwrap()), AsId::from(3), 16),
        ];
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        storage.add_records(records.clone(), PathBuf::new(), &trust_anchor);
        assert_eq!(
            storage.find_records(&IpNetwork::V6("dead:beef::/32".parse().unwrap())),
            [ records[0].clone(), records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V6("dead:be00::/24".parse().unwrap())),
            [ records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V6("dead:be00::/32".parse().unwrap())),
            [ records[2].clone() ]
        );
        assert_eq!(
            storage.find_records(&IpNetwork::V6("feed:be00::/24".parse().unwrap())),
            []
        );
    }

    #[test]
    fn duplicate_records() {
        let mut storage = RecordStorage::new();
        let records = vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 24),
        ];
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        // Add the same records twice for 2 different paths
        storage.add_records(records.clone(), PathBuf::from("asd"), &trust_anchor);
        storage.add_records(records.clone(), PathBuf::from("dsa"), &trust_anchor);
        assert_eq!(
            storage.find_records(&IpNetwork::V4("1.2.3.0/24".parse().unwrap())),
            records
        );
    }

    #[test]
    fn record_modification() {
        let mut storage = RecordStorage::new();
        let records1 = vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 24),
            Record::new(IpNetwork::V4("1.2.0.0/16".parse().unwrap()), AsId::from(1), 24),
        ];
        let records2 = vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 25),
        ];
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        let path = PathBuf::from("asd");
        storage.add_records(records1.clone(), path.clone(), &trust_anchor);
        storage.add_records(records2.clone(), path.clone(), &trust_anchor);
        // We should find records2 as it overrides the records in record1
        assert_eq!(
            storage.find_records(&IpNetwork::V4("1.2.3.0/24".parse().unwrap())),
            records2
        );
        assert_eq!(1, storage.total_records(trust_anchor.name()));
    }

    #[test]
    fn record_counts() {
        let mut storage = RecordStorage::new();
        let records1 = vec![
            Record::new(IpNetwork::V4("1.2.0.0/16".parse().unwrap()), AsId::from(1), 24),
        ];
        let records2 = vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 25),
        ];
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        // Add them in two runs
        storage.add_records(records1.clone(), PathBuf::from("asd"), &trust_anchor);
        storage.add_records(records2.clone(), PathBuf::from("dsa"), &trust_anchor);

        assert_eq!(2, storage.total_records(trust_anchor.name()));
    }
}
