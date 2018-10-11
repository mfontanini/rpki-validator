extern crate actix_web;
extern crate chrono;
#[macro_use] extern crate log;
extern crate ipnetwork;
extern crate num_cpus;
extern crate prometheus;
extern crate rpki_validator;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
extern crate simple_logger;
extern crate toml;
extern crate clap;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::{http, server, App, HttpRequest, HttpResponse};
use actix_web::dev::Handler;

use chrono::Local;
use chrono::DateTime;

use ipnetwork::IpNetwork;

use prometheus::{Encoder, Registry, TextEncoder};

use rpki_validator::executor::{Executor, Work};
use rpki_validator::metrics::Metrics;
use rpki_validator::processor::Processor;
use rpki_validator::rsync::RsyncFetcher;
use rpki_validator::storage::{RecordStorage, Record};
use rpki_validator::validation::{RecordValidator, ValidationRecords, ValidationResult};

struct AppState {
    validator: RecordValidator,
    storage: Arc<Mutex<RecordStorage>>,
    status: Arc<Mutex<ProcessingStatus>>,
}

impl AppState {
    fn new(validator: RecordValidator,
           storage: Arc<Mutex<RecordStorage>>,
           status: Arc<Mutex<ProcessingStatus>>)
        -> Self
    {
        AppState {
            validator,
            storage,
            status,
        }
    }
}

// API responses

enum ApiResponse<'a> {
    Error(String),
    ValidationResponse(IpNetwork, u32, ValidationResult),
    ExportResponse(Vec<Record>),
    StatusResponse(&'a HashMap<String, TrustAnchorStatus>),
}

impl<'a> ApiResponse<'a> {
    fn build(self) -> HttpResponse {
        let (mut response, body) = match self {
            ApiResponse::Error(message) => {
                (HttpResponse::BadRequest(), json!({"message": message}))
            },
            ApiResponse::ValidationResponse(prefix, asn, result) => {
                (HttpResponse::Ok(), ApiResponse::build_validation_body(prefix, asn, result))
            },
            ApiResponse::ExportResponse(records) => {
                (HttpResponse::Ok(), ApiResponse::build_export_body(records))
            },
            ApiResponse::StatusResponse(trust_anchors_statuses) => {
                (HttpResponse::Ok(), ApiResponse::build_status_body(trust_anchors_statuses))
            },
        };
        response.content_type("application/json")
                .body(body.to_string())
    }

    fn build_validation_body(prefix: IpNetwork, asn: u32, result: ValidationResult)
         -> serde_json::Value
    {
        let (state, reason, description, records) = match result {
            ValidationResult::Valid(records) => {
                ("Valid", "", "VRPs cover prefix", records)
            },
            ValidationResult::InvalidOrigin(records) => {
                ("Invalid", "as", "VRPs cover prefix but the origin is different", records)
            },
            ValidationResult::InvalidPrefixLength(records) => {
                ("Invalid", "length", "VRPs cover prefix but the length is larger than allowed",
                 records)
            },
            ValidationResult::NotFound => {
                ("NotFound", "", "No VRP covers the prefix", ValidationRecords::default())
            },
        };
        let records_to_json = |records: &Vec<Record>| {
            let mut output = Vec::new();
            for record in records {
                output.push(
                    json!({
                        "asn": format!("{}", record.origin()),
                        "prefix": format!("{}", record.prefix()),
                        "max_length": record.max_length(),
                    })
                );
            }
            output
        };
        json!({
            "validated_route": {
                "route": {
                    "origin_asn": format!("AS{}", asn),
                    "prefix": format!("{}", prefix)
                },
                "validity": {
                    "state": state,
                    "reason": reason,
                    "description": description,
                    "VRPs": {
                        "matched": records_to_json(records.matched()),
                        "unmatched_as": records_to_json(records.unmatched_origin()),
                        "unmatched_length": records_to_json(records.unmatched_length()),
                    }
                }
            }
        })
    }

    fn build_export_body(records: Vec<Record>) -> serde_json::Value {
        json!({
            "roas": records.into_iter().map(|r| {
                json!({
                    "prefix": format!("{}", r.prefix()),
                    "asn": format!("{}", r.origin()),
                    "maxLength": r.max_length(),
                })
            }).collect::<Vec<_>>()
        })
    }

    fn build_status_body(trust_anchors_statuses: &HashMap<String, TrustAnchorStatus>)
        -> serde_json::Value
    {
        let updated_anchor_count = trust_anchors_statuses.iter()
            .filter(|(_, status)| status.successful_runs > 0)
            .count();
        let service_status = if updated_anchor_count == trust_anchors_statuses.len() {
            "Ready"
        } else {
            "Updating"
        };
        json!({
            "anchors" : trust_anchors_statuses.iter().map(|(name, status)| {
                let last_run = status.last_run.map(|d| format!("{}",
                                                               d.format("%Y-%m-%d %H:%M:%S")));
                let duration = status.last_duration.map(|d| format!("{}.{}s", d.as_secs(),
                                                            d.subsec_millis()));
                json!({
                    "name": name.as_str(),
                    "successful_runs": status.successful_runs,
                    "error_runs": status.error_runs,
                    "last_run": last_run,
                    "last_update_duration": duration
                })
            }).collect::<Vec<_>>(),
            "updated_anchors": updated_anchor_count,
            "status": service_status,
        })
    }
}

// API calls

struct Api {

}

impl Api {
    fn validate(req: &HttpRequest<AppState>) -> HttpResponse {
        let match_info = req.match_info();
        let prefix = format!("{}/{}", &match_info["prefix"], &match_info["length"]);
        let prefix = match prefix.parse() {
            Ok(p) => p,
            Err(_) => return ApiResponse::Error("Invalid prefix".to_string()).build(),
        };
        let asn = match match_info["asn"].parse() {
            Ok(a) => a,
            Err(_) =>  return ApiResponse::Error("Invalid ASN".to_string()).build(),
        };
        let result = req.state().validator.validate(&prefix, asn);
        ApiResponse::ValidationResponse(prefix, asn, result).build()
    }

    fn export(req: &HttpRequest<AppState>) -> HttpResponse {
        let records = req.state().storage.lock().unwrap().records();
        ApiResponse::ExportResponse(records).build()
    }

    fn status(req: &HttpRequest<AppState>) -> HttpResponse {
        let status = req.state().status.lock().unwrap();
        ApiResponse::StatusResponse(status.trust_anchor_statuses()).build()
    }
}

// Metrics

struct MetricsHandler {
    registry: Registry,
}

impl MetricsHandler {
    fn new(registry: Registry) -> Self {
        MetricsHandler {
            registry
        }
    }
}

impl<S> Handler<S> for MetricsHandler {
    type Result = HttpResponse;

    fn handle(&self, _: &HttpRequest<S>) -> Self::Result {
        let mut buffer = Vec::<u8>::new();
        let encoder = TextEncoder::new();
        let metric_familys = self.registry.gather();
        for mf in metric_familys {
            if let Err(e) = encoder.encode(&[mf], &mut buffer) {
                warn!("ignoring prometheus encoding error: {:?}", e);
            }
        }
        String::from_utf8(buffer.clone()).unwrap().into()
    }
}

// Misc

struct ProcessingStatus {
    trust_anchors: HashMap<String, TrustAnchorStatus>,
}

impl ProcessingStatus {
    fn new() -> Self {
        ProcessingStatus {
            trust_anchors: HashMap::new(),
        }
    }

    fn create_trust_anchor(&mut self, name: &str) {
        self.trust_anchors.insert(name.to_string(), TrustAnchorStatus::default());
    }

    fn mark_successful_run(&mut self, trust_anchor_name: &str, last_run: DateTime<Local>,
                           last_duration: Duration) {
        let status = self.get_entry(trust_anchor_name, last_run, last_duration);
        status.successful_runs += 1;
    }

    fn mark_error_run(&mut self, trust_anchor_name: &str, last_run: DateTime<Local>,
                      last_duration: Duration) {
        let entry = self.get_entry(trust_anchor_name, last_run, last_duration);
        entry.error_runs += 1;
    }

    fn get_entry(&mut self, trust_anchor_name: &str, last_run: DateTime<Local>,
                 last_duration: Duration)
        -> &mut TrustAnchorStatus
    {
        let entry = self.trust_anchors.entry(trust_anchor_name.to_string()).or_default();
        entry.last_run = Some(last_run);
        entry.last_duration = Some(last_duration);
        entry
    }

    fn trust_anchor_statuses(&self) -> &HashMap<String, TrustAnchorStatus> {
        &self.trust_anchors
    }
}

#[derive(Default)]
struct TrustAnchorStatus {
    successful_runs: u64,
    error_runs: u64,
    last_run: Option<DateTime<Local>>,
    last_duration: Option<Duration>
}

// Work

struct ProcessorWork {
    processor: Processor,
    status: Arc<Mutex<ProcessingStatus>>,
    storage: Arc<Mutex<RecordStorage>>,
    metrics: Metrics,
}

impl ProcessorWork {
    fn new(processor: Processor,
           status: Arc<Mutex<ProcessingStatus>>,
           storage: Arc<Mutex<RecordStorage>>,
           metrics: Metrics)
        -> Self
    {
        ProcessorWork {
            processor,
            status,
            storage,
            metrics,
        }
    }
}

impl Work for ProcessorWork {
    fn execute(&mut self) -> Option<Instant> {
        info!("Running update on {} trust anchor", self.processor.trust_anchor_name());
        let now = Instant::now();
        let update_result = self.processor.update();
        let elapsed = now.elapsed();
        let name = self.processor.trust_anchor_name();
        {
            let mut status = self.status.lock().unwrap();
            match update_result {
                Ok(_) => {
                    status.mark_successful_run(name, Local::now(), elapsed)
                },
                Err(e) => {
                    status.mark_error_run(name, Local::now(), elapsed);
                    error!("Failed to update {} trust anchor: {}", name, e);
                }
            }
        }

        let total_records = self.storage.lock().unwrap().total_records(name);
        self.metrics.set_total_records(name, total_records as i64);
        self.metrics.observe_update_time(name, elapsed);
        Some(self.processor.next_update_time())
    }
}

#[derive(Deserialize)]
struct Config {
    rsync: RsyncConfig,
    tal: TalConfig,
    validation: ValidationConfig,
    api_server: ApiServerConfig
}

#[derive(Deserialize)]
struct RsyncConfig {
    #[serde(default = "default_rsync")]
    binary: String,
    interval: u32,
    #[serde(default = "default_cache_path")]
    cache_path: String,
}

#[derive(Deserialize)]
struct TalConfig {
    #[serde(default = "default_tal_path")]
    directory: String,
}

#[derive(Deserialize)]
struct ValidationConfig {
    #[serde(default)]
    strict: bool,
    #[serde(default = "num_cpus::get")]
    threads: usize,
}

#[derive(Deserialize)]
struct ApiServerConfig {
    #[serde(default = "default_api_endpoint")]
    endpoint: String
}

fn default_rsync() -> String {
    "rsync".to_string()
}

fn default_tal_path() -> String {
    env::var("TAL_PATH").unwrap_or("tal".to_string())
}

fn default_cache_path() -> String {
    env::var("CACHE_PATH").unwrap_or("/tmp/cache".to_string())
}

fn default_api_endpoint() -> String {
    env::var("API_ENDPOINT").unwrap_or("127.0.0.1:8080".to_string())
}

fn parse_config(path: &str) -> Option<Config> {
    info!("Using config file {}", path);
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open config file: {:}", e);
            return None;
        }
    };
    let mut contents = String::new();
    match file.read_to_string(&mut contents) {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to read config file: {:}", e);
            return None;
        }
    };
    //let config : Config = toml::from_str(&contents);
    match toml::from_str(&contents) {
        Ok(c) => Some(c),
        Err(e) => {
            error!("Failed to parse config file: {:}", e);
            None
        }
    }
}

fn bootstrap(storage: &Arc<Mutex<RecordStorage>>,
             executor: &mut Executor,
             status: &Arc<Mutex<ProcessingStatus>>,
             metrics: &Metrics,
             config: &Config) 
    -> bool
{
    let entries = match fs::read_dir(&config.tal.directory) {
        Ok(e) => e,
        Err(e) => {
            error!("Error processing TAL directory \"{}\": {}", config.tal.directory, e);
            return false;
        }
    };
    for entry in entries {
        let entry = entry.unwrap().path();
        info!("Creating processor for file {:?}", entry);
        let fetcher = RsyncFetcher::new(&config.rsync.binary);
        let processor = Processor::new(
            entry,
            &config.rsync.cache_path,
            config.validation.strict,
            fetcher,
            storage.clone(),
            Duration::from_secs(config.rsync.interval as u64 * 60),
        );
        // Create and entry in our status handler so we know it exists
        status.lock().unwrap().create_trust_anchor(processor.trust_anchor_name());

        // Create a Work for this processor
        executor.add_work(
            Box::new(ProcessorWork::new(
                processor,
                status.clone(),
                storage.clone(),
                metrics.clone()
            )),
            Instant::now()
        );
    }
    return true;
}

fn main() {
    let matches = clap::App::new("RPKI validator")
                      .version("0.1.0")
                      .author("Matias Fontanini")
                      .about("Syncs and validates RPKI records")
                      .arg(clap::Arg::with_name("config")
                           .short("c")
                           .long("config")
                           .value_name("FILE")
                           .help("The config file to use")
                           .takes_value(true)
                           .required(true))
                       .get_matches();

    simple_logger::init_with_level(log::Level::Info).unwrap();

    let config = match parse_config(matches.value_of("config").unwrap()) {
        Some(c) => c,
        None => return,
    };

    if let Err(e) = RsyncFetcher::new(&config.rsync.binary).check_rsync_binary() {
        error!("Failed to execute rsync binary: {}", e);
        return;
    }

    // Setup prometheus metrics
    let metrics = Metrics::new();
    let mut registry = Registry::new();
    metrics.register(&mut registry);

    // Setup our processing blocks
    let storage = Arc::new(Mutex::new(RecordStorage::new()));
    let mut executor = Executor::new(config.validation.threads);
    let status = Arc::new(Mutex::new(ProcessingStatus::new()));

    // Bootstrap our processing
    if !bootstrap(&storage, &mut executor, &status, &metrics, &config) {
        return;
    }

    // Start the API
    server::new(
        move || {
            let registry = registry.clone();
            vec![
                // API handler
                App::with_state(AppState::new(RecordValidator::new(storage.clone()),
                                              storage.clone(), status.clone()))
                    .prefix("/api/v1")
                    .resource(
                        "/validity/AS{asn}/{prefix}/{length}",
                        |r| r.method(http::Method::GET).f(Api::validate)
                    )
                    .resource(
                        "/status",
                        |r| r.method(http::Method::GET).f(Api::status)
                    )
                    .resource(
                        "/export.json",
                        |r| r.method(http::Method::GET).f(Api::export)
                    )
                    .boxed(),
                // Metrics handler
                App::new()
                    .prefix("/mgmt")
                    .resource("/metrics", move |r| {
                        r.method(http::Method::GET).h(MetricsHandler::new(registry.clone()))
                    }).boxed(),
            ]
        }).bind(config.api_server.endpoint).unwrap()
          .workers(4)
          .run();
}
