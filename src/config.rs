use std::env;
use std::io::Read;
use std::fs::File;

use num_cpus;
use toml;

#[derive(Deserialize)]
pub struct Config {
    pub rsync: RsyncConfig,
    #[serde(default)]
    pub tal: TalConfig,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub api_server: ApiServerConfig
}

impl Config {
    pub fn from_path(path: &str) -> Option<Config> {
        info!("Using config file {}", path);
        let mut file = match File::open(path) {
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
        match toml::from_str(&contents) {
            Ok(c) => Some(c),
            Err(e) => {
                error!("Failed to parse config file: {:}", e);
                None
            }
        }
    }
}

// RsyncConfig

#[derive(Deserialize)]
pub struct RsyncConfig {
    #[serde(default = "default_rsync")]
    pub binary: String,
    pub interval: u32,
    #[serde(default = "default_cache_path")]
    pub cache_path: String,
}

fn default_rsync() -> String {
    "rsync".to_string()
}

fn default_cache_path() -> String {
    env::var("CACHE_PATH").unwrap_or("/tmp/rpki-validator-cache".to_string())
}

// TalConfig

#[derive(Deserialize)]
pub struct TalConfig {
    #[serde(default = "default_tal_directory")]
    pub directory: String,
}

impl Default for TalConfig {
    fn default() -> Self {
        TalConfig {
            directory: default_tal_directory()
        }
    }
}

fn default_tal_directory() -> String {
    env::var("TAL_PATH").unwrap_or("tal".to_string())
}

// ValidationConfig

#[derive(Deserialize)]
#[serde(default)]
pub struct ValidationConfig {
    pub strict: bool,
    pub threads: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        ValidationConfig {
            strict: false,
            threads: num_cpus::get()
        }
    }
}

// ApiServerConfig

#[derive(Deserialize)]
#[serde(default)]
pub struct ApiServerConfig {
    pub endpoint: String
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        ApiServerConfig {
            endpoint: env::var("API_ENDPOINT").unwrap_or("127.0.0.1:8080".to_string())
        }
    }
}
