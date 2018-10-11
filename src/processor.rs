use std::collections::{HashMap, HashSet};
use std::io;
use std::io::Read;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{File, create_dir_all};
use std::path::{PathBuf, Path};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use ipnetwork::IpNetwork;

use rpki::cert::{Cert, ResourceCert};
use rpki::crl::{Crl, CrlStore};
use rpki::manifest::{Manifest, ManifestContent, ManifestHash};
use rpki::roa::{Roa, RouteOriginAttestation};
use rpki::tal::{Tal, ReadError};
use rpki::uri;
use rpki::x509;

use rsync::{RsyncAction, RsyncFetcher};
use storage::{Record, RecordStorage, TrustAnchor};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tal(ReadError),
    Generic(&'static str),
    Validation,
    Other,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => e.fmt(f),
            Error::Tal(e) => e.fmt(f),
            Error::Generic(e) => write!(f, "{}", e),
            Error::Validation => write!(f, "Failed to validate record"),
            Error::Other => write!(f, "Unknown error"),
        }
    }
}

// ProcessingPolicy

trait ModuleProcess {
    fn should_process_module(&self) -> bool;
    fn should_process_file(&self, file_path: &Path) -> bool;
    fn remove_deleted_files(&self, storage: &mut RecordStorage);
}

struct AlwaysProcess {

}

impl ModuleProcess for AlwaysProcess {
    fn should_process_module(&self) -> bool {
        true
    }

    fn should_process_file(&self, _file_path: &Path) -> bool {
        true
    }

    fn remove_deleted_files(&self, _storage: &mut RecordStorage) {

    }
}

struct ProcessModified {
    new_files : HashSet<PathBuf>,
    modified_files : HashSet<PathBuf>,
    deleted_files : HashSet<PathBuf>,
}

impl ProcessModified {
    fn new() -> ProcessModified {
        ProcessModified {
            new_files : HashSet::new(),
            modified_files : HashSet::new(),
            deleted_files  : HashSet::new(),
        }
    }

    fn add_new_file(&mut self, path: PathBuf) {
        self.new_files.insert(path);
    }

    fn add_modified_file(&mut self, path: PathBuf) {
        self.modified_files.insert(path);
    }

    fn add_deleted_file(&mut self, path: PathBuf) {
        self.deleted_files.insert(path);
    }
}

impl ModuleProcess for ProcessModified {
    fn should_process_module(&self) -> bool {
        !self.new_files.is_empty() || !self.modified_files.is_empty()
    }

    fn should_process_file(&self, file_path: &Path) -> bool {
        self.new_files.contains(file_path) || self.modified_files.contains(file_path)
    }

    fn remove_deleted_files(&self, storage: &mut RecordStorage) {
        if !self.deleted_files.is_empty() {
            info!("Removing state for {} deleted files", self.deleted_files.len());
            storage.remove_records(self.deleted_files.iter());
        }
    }
}

#[derive(Clone)]
pub enum ProcessingPolicyType {
    DownloadAndProcess,
    ProcessExisting,
    ProcessChanged,
}

#[derive(Clone)]
pub struct ProcessingPolicy {
    policy_type: ProcessingPolicyType,
    next_processing_offset: Duration,
    cached_module_processors: HashMap<PathBuf, Arc<ModuleProcess + Sync + Send>>,
}

impl ProcessingPolicy {
    pub fn new(policy_type: ProcessingPolicyType) -> Self {
        ProcessingPolicy {
            policy_type,
            next_processing_offset: Duration::default(),
            cached_module_processors: HashMap::new(),
        }
    }

    fn next(&self, default_execution_offset: Duration) -> ProcessingPolicy {
        // If have just processed the existing ones, we want to immediately rsync and process
        // all changes. Otherwise, we've already rsync'd, let's wait until our scheduled
        // execution time and process modifications by then
        let (policy, offset) = match self.policy_type {
            ProcessingPolicyType::ProcessExisting => {
                (ProcessingPolicyType::ProcessChanged, Duration::default())
            },
            ProcessingPolicyType::ProcessChanged | ProcessingPolicyType::DownloadAndProcess => {
                (ProcessingPolicyType::ProcessChanged, default_execution_offset)
            },
        };
        ProcessingPolicy {
            policy_type: policy,
            next_processing_offset: offset,
            cached_module_processors: HashMap::new(),
        }
    }

    fn next_process_time(&self) -> Instant {
        Instant::now() + self.next_processing_offset
    }

    fn do_load_module(&mut self,
                      uri: &uri::Rsync,
                      output_path: &Path,
                      rsync_fetcher: &RsyncFetcher)
        -> Result<Arc<ModuleProcess + Sync + Send>, Error>
    {
        // Don't fetch anything if we're only trying to process the existing ones
        match self.policy_type {
            ProcessingPolicyType::ProcessExisting => {
                return Ok(Arc::new(AlwaysProcess{}))
            },
            _ => (),
        };
        let uri = uri::Rsync::new(uri.to_module(), Bytes::new());
        info!("Downloading files for directory {:?}", output_path);
        create_dir_all(&output_path)?;
        let rsync_output = rsync_fetcher.fetch(
            &uri,
            output_path
        )?;
        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();
        for action in rsync_output.actions() {
            match action {
                RsyncAction::CreateFile(p) => created.push(p),
                RsyncAction::ModifyFile(p) => modified.push(p),
                RsyncAction::DeleteFile(p) => deleted.push(p),
            }
        }
        info!(
            "Downloaded directory {:?}, {} created, {} modified, {} deleted",
            output_path,
            created.len(),
            modified.len(),
            deleted.len()
        );
        match self.policy_type {
            // We already downloaded, now we just have to process all of them
            ProcessingPolicyType::DownloadAndProcess => {
                return Ok(Arc::new(AlwaysProcess{}));
            },
            ProcessingPolicyType::ProcessChanged => {
                let mut output = ProcessModified::new();
                created.into_iter().for_each(|p| output.add_new_file(p));
                modified.into_iter().for_each(|p| output.add_modified_file(p));
                deleted.into_iter().for_each(|p| output.add_deleted_file(p));
                return Ok(Arc::new(output));
            },
            _ => panic!(""),
        }
    }


    fn load_module(&mut self,
                   uri: &uri::Rsync,
                   output_path: &Path,
                   rsync_fetcher: &RsyncFetcher)
        -> Result<Arc<ModuleProcess>, Error>
    {
        if let Some(cached_entry) = self.cached_module_processors.get(output_path) {
            return Ok(cached_entry.clone());
        }
        let output = self.do_load_module(uri, output_path, rsync_fetcher)?;
        self.cached_module_processors.insert(output_path.to_path_buf(), output.clone());
        Ok(output)
    }

    fn remove_deleted_files(&self, storage: &mut RecordStorage) {
        for (_, entry) in self.cached_module_processors.iter() {
            entry.remove_deleted_files(storage);
        }
    }
}

// Processor

// The code in this class is based on the validation code
// in routinator (https://github.com/NLnetLabs/routinator)

// A processor is in charge of rsyncing and processing a single repository. It tries to
// be efficient and not reprocess everything if only a subset or none of the files were modified
// when rsyncing.
pub struct Processor {
    tal_path: PathBuf,
    trust_anchor: Arc<TrustAnchor>,
    output_path: String,
    strict_mode: bool,
    rsync_fetcher: RsyncFetcher,
    storage: Arc<Mutex<RecordStorage>>,
    processing_interval : Duration,
    policy: ProcessingPolicy,
}

impl Processor {
    pub fn new(tal_path: PathBuf,
               output_path: &str,
               strict_mode: bool,
               rsync_fetcher: RsyncFetcher,
               storage: Arc<Mutex<RecordStorage>>,
               processing_interval: Duration)
        -> Self
    {
        let name = match tal_path.file_stem().and_then(OsStr::to_str).map(str::to_string) {
            Some(n) => n,
            None => {
                warn!("Failed to get file stem for {:?}", tal_path);
                tal_path.to_string_lossy().to_string()
            },
        };
        Processor {
            tal_path,
            trust_anchor: Arc::new(TrustAnchor::new(name)),
            output_path: output_path.to_string(),
            strict_mode,
            rsync_fetcher,
            storage,
            processing_interval,
            policy: ProcessingPolicy::new(ProcessingPolicyType::DownloadAndProcess),
        }
    }

    pub fn next_update_time(&self) -> Instant {
        self.policy.next_process_time()
    }

    pub fn trust_anchor_name(&self) -> &str {
        &self.trust_anchor.name()
    }

    pub fn update(&mut self) -> Result<(), Error> {
        let mut file = match File::open(&*self.tal_path.to_string_lossy()) {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to open TAL file {:?}: {}", self.tal_path, e);
                return Err(Error::Io(e));
            }
        };
        info!("Processing tal file {:?}", self.tal_path);
        let tal = match Tal::read(&self.tal_path, &mut file) {
            Ok(tal) => tal,
            Err(e) => {
                error!("Failed to parse TAL file: {}", e);
                return Err(Error::Tal(e));
            }
        };
        // Process this TAL file
        let output = self.process_tal(tal);
        // Process any file deletions
        self.policy.remove_deleted_files(&mut self.storage.lock().unwrap());
        // Now change our policy and then return
        self.policy = self.policy.next(self.processing_interval);
        output
    }

    fn process_tal(&mut self, tal: Tal) -> Result<(), Error> {
        for uri in tal.uris() {
            let output_path = self.get_module_path(uri);
            self.policy.load_module(
                uri,
                &output_path,
                &self.rsync_fetcher
            )?;
            let bytes = match self.load_file(uri)? {
                Some(b) => b,
                None => continue,
            };
            let path = self.get_path(uri);
            info!("Processing TAL file {:?}", path);
            let cert = self.extract_certificate(bytes, &tal)?;
            self.process_certificate(cert)?;
            info!("Finished processing {:?}", path);
        }
        Ok(())
    }

    fn get_module_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut output = PathBuf::new();
        output.push(&self.output_path);
        output.push(uri.module().authority());
        output.push(uri.module().module());
        output
    }

    fn get_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut output = self.get_module_path(uri);
        output.push(uri.path());
        output
    }

    fn load_file(&self, uri: &uri::Rsync) -> Result<Option<Bytes>, Error> {
        let file_path = self.get_path(uri);
        let file = File::open(&file_path);
        match file {
            Ok(mut file) => {
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                Ok(Some(Bytes::from(buffer)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                warn!("Ignoring file not found {:?}", file_path);
                Ok(None)
            },
            Err(e) => Err(Error::Io(e))
        }
    }

    fn rsync_load_file(&mut self, uri: &uri::Rsync) -> Result<Option<Bytes>, Error> {
        let output_path = self.get_module_path(uri);
        self.policy.load_module(
            uri,
            &output_path,
            &self.rsync_fetcher,
        )?;
        self.load_file(uri)
    }

    fn extract_certificate(&self, data: Bytes, tal: &Tal) -> Result<ResourceCert, Error> {
        let cert = Cert::decode(data)
            .map_err(|_| Error::Generic("Failed to decode certificate"))?;
        if cert.subject_public_key_info() != tal.key_info() {
            warn!("Found cert signed by different key that source TAL file");
            return Err(Error::Other);
        }
        cert.validate_ta(self.strict_mode).map_err(|_| Error::Other)
    }

    fn process_certificate(&mut self, issuer_cert: ResourceCert) -> Result<(), Error> {
        let repo_uri = match issuer_cert.repository_uri() {
            Some(uri) => uri,
            None => return Ok(())
        };
        let output_path = self.get_module_path(&repo_uri);
        let module_processor = self.policy.load_module(
            &repo_uri,
            &output_path,
            &self.rsync_fetcher
        )?;
        if !module_processor.should_process_module() {
            info!("Skipping unmodified certificate file {:?}", output_path);
            return Ok(());
        }
        let mut crl_store = CrlStore::new();
        let manifest = match self.get_manifest(&issuer_cert, &mut crl_store)? {
            Some(manifest) => manifest,
            None => return Ok(())
        };

        self.process_manifest(
            issuer_cert,
            manifest,
            crl_store,
            module_processor,
            repo_uri
        )
    }

    fn process_manifest(&mut self,
                        issuer_cert: ResourceCert,
                        manifest: ManifestContent,
                        mut crl_store: CrlStore,
                        module_processor: Arc<ModuleProcess>,
                        repo_uri: uri::Rsync)
        -> Result<(), Error> {
        for item in manifest.iter_uris(repo_uri.clone()) {
            let (uri, hash) = match item {
                Ok(item) => item,
                Err(e) => {
                    warn!("Verification failed for {}: {}", repo_uri, e);
                    continue;
                },
            };
            let path = self.get_path(&uri);
            // Ignore if it it's not modified and it's not a certificate file
            if !module_processor.should_process_file(&path) && !uri.ends_with(".cer") {
                debug!("Skipping unmodified file {:?}", path);
                continue;
            }
            debug!("Processing file {:?}", path);
            let routes = self.process_object(
                &uri,
                hash,
                &issuer_cert,
                &mut crl_store
            );
            let routes = match routes {
                Ok(routes) => routes,
                Err(_) => continue,
            };
            if let Some(routes) = routes {
                let records = routes.iter().map(|address| {
                    let prefix = IpNetwork::new(address.address(), address.address_length());
                    match prefix {
                        Ok(prefix) => {
                            let record = Record::new(
                                prefix,
                                routes.as_id(),
                                address.max_length()
                            );
                            Some(record)
                        },
                        Err(_) => None
                    }
                }).filter(Option::is_some).map(Option::unwrap).collect::<Vec<_>>();
                self.storage.lock().unwrap().add_records(records, path, &self.trust_anchor);
            }
        }
        Ok(())
    }

    fn get_manifest(&mut self, issuer_cert: &ResourceCert, store: &mut CrlStore)
        -> Result<Option<ManifestContent>, Error>
    {
        for uri in issuer_cert.manifest_uris() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue,
            };
            let bytes = match self.rsync_load_file(&uri)? {
                Some(b) => b,
                None => continue,
            };
            let manifest = match Manifest::decode(bytes, self.strict_mode) {
                Ok(manifest) => manifest,
                Err(_) => {
                    warn!("Failed to decode manifest for URI {:?}", uri);
                    continue
                }
            };
            let (cert, manifest) = match manifest.validate(issuer_cert, self.strict_mode) {
                Ok(manifest) => manifest,
                Err(_) => {
                    info!("Failed to validate manifest for URI {:?}", uri);
                    continue
                }
            };
            if let Err(_) = self.check_crl(cert.as_ref(), issuer_cert, store) {
                info!("Certificate for URI {:?} has been revoked", uri);
                continue
            }
            return Ok(Some(manifest))
        }
        Ok(None)
    }

    fn check_crl(&mut self, cert: &Cert, issuer_cert: &ResourceCert, store: &mut CrlStore)
        -> Result<(), Error>
    {
        let uri_list = match cert.crl_distribution() {
            Some(some) => some,
            None => return Ok(())
        };
        for uri in uri_list.iter() {
            let uri = match uri.into_rsync_uri() {
                Some(uri) => uri,
                None => continue
            };

            // If we already have that CRL, use it.
            if let Some(crl) = store.get(&uri) {
                if crl.contains(&cert.serial_number()) {
                    return Err(Error::Validation)
                }
                else {
                    return Ok(())
                }
            }

            // Otherwise, try to load it, use it, and then store it.
            let bytes = match self.rsync_load_file(&uri)? {
                Some(b) => b,
                None => continue,
            };
            let crl = match Crl::decode(bytes) {
                Ok(crl) => crl,
                Err(_) => continue
            };
            if let Err(_) = crl.validate(issuer_cert) {
                continue
            }

            let revoked = crl.contains(&cert.as_ref().serial_number());
            store.push(uri, crl);
            if revoked {
                return Err(Error::Validation)
            }
            else {
                return Ok(())
            }
        }
        Err(Error::Validation)
    }

    fn process_object(&mut self,
                      uri: &uri::Rsync,
                      hash: ManifestHash,
                      issuer_cert: &ResourceCert,
                      store: &mut CrlStore)
        -> Result<Option<RouteOriginAttestation>, Error>
    {
        if uri.ends_with(".cer") {
            let bytes = match self.load_file(&uri)? {
                Some(b) => b,
                None => return Ok(None),
            };
            if hash.verify(&bytes).is_err() {
                info!("Verification of file {:?} failed", self.get_path(uri));
                return Ok(None)
            }
            let cert = match Cert::decode(bytes) {
                Ok(cert) => cert,
                Err(e) => {
                    info!("Failed to decode certificate {:?} {:?}", self.get_path(uri), e);
                    return Ok(None)
                }
            };
            let cert = match cert.validate_ca(issuer_cert, self.strict_mode) {
                Ok(cert) => cert,
                Err(_) => {
                    info!("Failed to validate CA {:?}", self.get_path(uri));
                    return Ok(None)
                }
            };
            if let Err(_) = self.check_crl(cert.as_ref(), issuer_cert, store) {
                info!("Certificate {:?} has been revoked", self.get_path(uri));
                return Ok(None)
            }
            self.process_certificate(cert)?;
        }
        else if uri.ends_with(".roa") {
            let bytes = match self.load_file(&uri)? {
                Some(b) => b,
                None => return Ok(None),
            };
            if let Err(_) = hash.verify(&bytes) {
                return Ok(None)
            }
            let roa = match Roa::decode(bytes, self.strict_mode) {
                Ok(roa) => roa,
                Err(_) => {
                    info!("Decoding failed for {:?}", self.get_path(uri));
                    return Ok(None)
                }
            };
            let route = roa.process(issuer_cert, self.strict_mode, |cert| {
                self.check_crl(cert, issuer_cert, store)
                    .map_err(|_| x509::ValidationError)
            });
            if let Ok(route) = route {
                return Ok(Some(route))
            }
        }
        else if !uri.ends_with(".crl") {
            info!("Skipping unknown file {:?}", self.get_path(uri));
        }
        Ok(None)
    }
}
