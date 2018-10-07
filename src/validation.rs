use std::sync::Arc;
use std::sync::Mutex;

use ipnetwork::IpNetwork;

use rpki::asres::AsId;

use storage::{RecordStorage, Record};

pub struct RecordValidator {
    storage: Arc<Mutex<RecordStorage>>,
}

impl RecordValidator {
    pub fn new(storage: Arc<Mutex<RecordStorage>>) -> Self {
        RecordValidator {
            storage
        }
    }

    pub fn validate(&self, prefix: &IpNetwork, origin: u32) -> ValidationResult {
        let origin = AsId::from(origin);
        let records = self.storage.lock().unwrap().find_records(prefix);
        let mut valid_records = Vec::new();
        let mut invalid_length = Vec::new();
        let mut invalid_origin = Vec::new();
        let mut found_valid_origin = false;
        // Iterate and classify them
        for record in records {
            let has_valid_length = record.max_length() >= prefix.prefix();
            let has_valid_origin = record.origin() == origin;
            if has_valid_origin && has_valid_length {
                valid_records.push(record);
            }
            else {
                if !has_valid_origin {
                    invalid_origin.push(record);
                }
                else if !has_valid_length {
                    invalid_length.push(record);
                }
            }
            found_valid_origin = found_valid_origin || has_valid_origin;
        }
        let records = ValidationRecords::new(
            valid_records,
            invalid_origin,
            invalid_length,
        );
        if !records.matched().is_empty() {
            ValidationResult::Valid(records)
        }
        else if !records.unmatched_origin().is_empty() || !records.unmatched_length().is_empty() {
            if records.unmatched_origin().is_empty() || found_valid_origin {
                ValidationResult::InvalidPrefixLength(records)
            }
            else {
                ValidationResult::InvalidOrigin(records)
            }
        }
        else {
            ValidationResult::NotFound
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct ValidationRecords {
    matched : Vec<Record>,
    unmatched_origin : Vec<Record>,
    unmatched_length : Vec<Record>,
}

impl ValidationRecords {
    pub fn new(matched: Vec<Record>,
               unmatched_origin: Vec<Record>,
               unmatched_length: Vec<Record>)
        -> Self
    {
        ValidationRecords {
            matched,
            unmatched_origin,
            unmatched_length
        }
    }

    pub fn matched(&self) -> &Vec<Record> {
        &self.matched
    }

    pub fn unmatched_origin(&self) -> &Vec<Record> {
        &self.unmatched_origin
    }

    pub fn unmatched_length(&self) -> &Vec<Record> {
        &self.unmatched_length
    }
}

// ValidationResult
#[derive(Debug, PartialEq)]
pub enum ValidationResult {
    Valid(ValidationRecords),
    InvalidOrigin(ValidationRecords),
    InvalidPrefixLength(ValidationRecords),
    NotFound,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationResult::Valid(_) => true,
            _ => false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use storage::TrustAnchor;

    use super::*;

    fn create_records() -> Vec<Record> {
        vec![
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(1), 26),
            Record::new(IpNetwork::V4("1.2.2.0/23".parse().unwrap()), AsId::from(1), 24),
            Record::new(IpNetwork::V4("1.2.0.0/16".parse().unwrap()), AsId::from(3), 16),
            Record::new(IpNetwork::V4("1.2.3.0/24".parse().unwrap()), AsId::from(4), 24),
            Record::new(IpNetwork::V4("4.4.4.0/24".parse().unwrap()), AsId::from(1), 26),
        ]
    }

    fn create_verifier(records: Vec<Record>) -> RecordValidator {
        let mut storage = RecordStorage::new();
        let trust_anchor = Arc::new(TrustAnchor::new("foo".to_string()));
        storage.add_records(records, PathBuf::new(), &trust_anchor);
        RecordValidator::new(Arc::new(Mutex::new(storage)))
    }

    #[test]
    fn verify_valid() {
        let records = create_records();
        let verifier = create_verifier(records.clone());

        assert_eq!(
            ValidationResult::Valid(
                ValidationRecords::new(
                    vec![ records[0].clone(), records[1].clone() ],
                    vec![ records[3].clone(), records[2].clone() ],
                    vec![],
                )
            ),
            verifier.validate(&IpNetwork::V4("1.2.3.0/24".parse().unwrap()), 1),
        );
        assert_eq!(
            ValidationResult::Valid(
                ValidationRecords::new(
                    vec![ records[0].clone() ],
                    vec![ records[3].clone(), records[2].clone() ],
                    vec![ records[1].clone() ],
                )
            ),
            verifier.validate(&IpNetwork::V4("1.2.3.0/25".parse().unwrap()), 1),
        );
    }

    #[test]
    fn verify_invalid_origin() {
        let records = create_records();
        let verifier = create_verifier(records.clone());

        assert_eq!(
            ValidationResult::InvalidOrigin(
                ValidationRecords::new(
                    vec![ ],
                    vec![
                        records[0].clone(),
                        records[3].clone(),
                        records[1].clone(),
                        records[2].clone(),
                    ],
                    vec![ ],
                )
            ),
            verifier.validate(&IpNetwork::V4("1.2.3.0/24".parse().unwrap()), 10),
        );
    }

    #[test]
    fn verify_invalid_prefix_length() {
        let records = create_records();
        let verifier = create_verifier(records.clone());

        assert_eq!(
            ValidationResult::InvalidPrefixLength(
                ValidationRecords::new(
                    vec![ ],
                    vec![ ],
                    vec![ records[4].clone() ],
                )
            ),
            verifier.validate(&IpNetwork::V4("4.4.4.0/27".parse().unwrap()), 1),
        );
    }

    #[test]
    fn verify_not_found() {
        let records = create_records();
        let verifier = create_verifier(records.clone());

        assert_eq!(
            ValidationResult::NotFound,
            verifier.validate(&IpNetwork::V4("3.3.3.0/24".parse().unwrap()), 1),
        );
        assert_eq!(
            ValidationResult::NotFound,
            verifier.validate(&IpNetwork::V4("1.2.0.0/15".parse().unwrap()), 1),
        );
    }
}
