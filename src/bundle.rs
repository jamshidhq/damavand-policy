//! Policy bundles: the files the engine loads.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::types::{BrokerKey, BundleId};

/// One policy file: its name (for error messages) and its Cedar text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyFile {
    pub(crate) name: String,
    pub(crate) text: String,
}

/// A policy bundle in memory.
///
/// On disk a bundle is a directory (a git checkout):
///
/// ```text
/// schema.cedarschema
/// autonomy.toml          (optional; absent = every cap is L0)
/// constraints.toml       (optional; absent = no parameter clears taint)
/// approval.toml          (optional; absent = no grant verifies)
/// global/*.cedar
/// projects/<id>/*.cedar
/// ```
///
/// `constraints.toml` maps (action, parameter) to an enum or an anchored
/// pattern; a match clears that parameter's taint:
///
/// ```toml
/// [j_edit.mode]
/// enum = ["append", "replace"]
///
/// [j_edit.path]
/// pattern = "[a-z0-9/._-]+"
/// ```
///
/// `approval.toml` lists the approval broker's Ed25519 public keys and,
/// optionally, the longest grant lifetime in seconds past the request's
/// `now` ([`DEFAULT_MAX_GRANT_TTL`] when absent):
///
/// ```toml
/// broker_keys = ["<64 hex characters>"]
/// max_grant_ttl = 3600
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub(crate) label: String,
    pub(crate) schema: String,
    pub(crate) global: Vec<PolicyFile>,
    pub(crate) projects: BTreeMap<String, Vec<PolicyFile>>,
    pub(crate) autonomy: String,
    pub(crate) constraints: String,
    pub(crate) broker_keys: Vec<BrokerKey>,
    pub(crate) max_grant_ttl: u64,
}

/// Longest grant lifetime, in seconds past the request's `now`, when the
/// bundle does not set `max_grant_ttl`: one hour.
pub const DEFAULT_MAX_GRANT_TTL: u64 = 3600;

impl Bundle {
    /// A bundle with a schema and no policies, caps, constraints or broker
    /// keys. `label` is a human label (a commit sha); the bundle id is a
    /// content digest computed by [`crate::Engine::load`].
    pub fn new(label: impl Into<String>, schema: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            schema: schema.into(),
            global: Vec::new(),
            projects: BTreeMap::new(),
            autonomy: String::new(),
            constraints: String::new(),
            broker_keys: Vec::new(),
            max_grant_ttl: DEFAULT_MAX_GRANT_TTL,
        }
    }

    /// Add a global policy file.
    pub fn with_global(mut self, file: impl Into<String>, text: impl Into<String>) -> Self {
        self.global.push(PolicyFile {
            name: file.into(),
            text: text.into(),
        });
        self
    }

    /// Add a policy file for a project.
    pub fn with_project(
        mut self,
        project: impl Into<String>,
        file: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        self.projects
            .entry(project.into())
            .or_default()
            .push(PolicyFile {
                name: file.into(),
                text: text.into(),
            });
        self
    }

    /// Set the `autonomy.toml` text.
    pub fn with_autonomy(mut self, toml: impl Into<String>) -> Self {
        self.autonomy = toml.into();
        self
    }

    /// Set the `constraints.toml` text.
    pub fn with_constraints(mut self, toml: impl Into<String>) -> Self {
        self.constraints = toml.into();
        self
    }

    /// Trust an approval broker's public key.
    pub fn with_broker_key(mut self, key: BrokerKey) -> Self {
        self.broker_keys.push(key);
        self
    }

    /// Set the longest grant lifetime in seconds past the request's `now`.
    /// A grant whose `expires_at` lies further out does not lift. It must be
    /// at least 1; [`crate::Engine::load`] refuses 0.
    pub fn with_max_grant_ttl(mut self, seconds: u64) -> Self {
        self.max_grant_ttl = seconds;
        self
    }

    /// The human label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// SHA-256 over the canonical content: every field length-prefixed,
    /// policy files sorted by name, projects by id. The label is not in it.
    pub(crate) fn digest(&self) -> BundleId {
        fn feed(h: &mut Sha256, b: &[u8]) {
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        }
        fn files(h: &mut Sha256, files: &[PolicyFile]) {
            let mut sorted: Vec<&PolicyFile> = files.iter().collect();
            sorted.sort_by(|a, b| (&a.name, &a.text).cmp(&(&b.name, &b.text)));
            h.update((sorted.len() as u64).to_be_bytes());
            for f in sorted {
                feed(h, f.name.as_bytes());
                feed(h, f.text.as_bytes());
            }
        }
        let mut h = Sha256::new();
        feed(&mut h, b"damavand-policy/bundle/v2");
        feed(&mut h, self.schema.as_bytes());
        feed(&mut h, self.autonomy.as_bytes());
        feed(&mut h, self.constraints.as_bytes());
        h.update((self.broker_keys.len() as u64).to_be_bytes());
        for k in &self.broker_keys {
            feed(&mut h, &k.0);
        }
        h.update(self.max_grant_ttl.to_be_bytes());
        files(&mut h, &self.global);
        h.update((self.projects.len() as u64).to_be_bytes());
        for (id, fs) in &self.projects {
            feed(&mut h, id.as_bytes());
            files(&mut h, fs);
        }
        BundleId(h.finalize().into())
    }

    /// Read a bundle directory. `label` is the commit sha of the checkout.
    /// Files are read in name order.
    pub fn from_dir(dir: &Path, label: impl Into<String>) -> Result<Bundle, LoadError> {
        let read = |p: &Path| {
            std::fs::read_to_string(p).map_err(|e| LoadError::Io {
                path: p.display().to_string(),
                message: e.to_string(),
            })
        };
        let optional = |name: &str| {
            let p = dir.join(name);
            if p.exists() {
                read(&p)
            } else {
                Ok(String::new())
            }
        };
        let schema = read(&dir.join("schema.cedarschema"))?;
        let mut bundle = Bundle::new(label, schema)
            .with_autonomy(optional("autonomy.toml")?)
            .with_constraints(optional("constraints.toml")?);
        let (keys, ttl) = parse_approval(&optional("approval.toml")?)?;
        for key in keys {
            bundle = bundle.with_broker_key(key);
        }
        if let Some(ttl) = ttl {
            bundle = bundle.with_max_grant_ttl(ttl);
        }
        for (name, text) in cedar_files(&dir.join("global"), read)? {
            bundle = bundle.with_global(format!("global/{name}"), text);
        }
        let projects = dir.join("projects");
        for project in sorted_entries(&projects)? {
            if !project.is_dir() {
                continue;
            }
            let pid = file_name(&project);
            for (name, text) in cedar_files(&project, read)? {
                bundle = bundle.with_project(pid.clone(), format!("projects/{pid}/{name}"), text);
            }
        }
        Ok(bundle)
    }
}

/// `approval.toml`: `broker_keys = ["<hex>", ...]`, optional
/// `max_grant_ttl = <seconds, at least 1>`, and nothing else.
fn parse_approval(text: &str) -> Result<(Vec<BrokerKey>, Option<u64>), LoadError> {
    let bad = |message: String| LoadError::Approval { message };
    let table: toml::Table = toml::from_str(text).map_err(|e| bad(e.message().to_string()))?;
    let mut keys = Vec::new();
    let mut ttl = None;
    for (k, v) in table {
        if k == "max_grant_ttl" {
            let secs = v
                .as_integer()
                .and_then(|n| u64::try_from(n).ok())
                .filter(|n| *n >= 1)
                .ok_or_else(|| bad("max_grant_ttl is a number of seconds, at least 1".into()))?;
            ttl = Some(secs);
            continue;
        }
        if k != "broker_keys" {
            return Err(bad(format!("unknown key {k:?}")));
        }
        let list = v
            .as_array()
            .ok_or_else(|| bad("broker_keys must be a list".into()))?;
        for item in list {
            let key = item
                .as_str()
                .and_then(|s| s.parse::<BrokerKey>().ok())
                .ok_or_else(|| bad("a broker key is 64 hex characters".into()))?;
            keys.push(key);
        }
    }
    Ok((keys, ttl))
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn sorted_entries(dir: &Path) -> Result<Vec<std::path::PathBuf>, LoadError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let io = |e: std::io::Error| LoadError::Io {
        path: dir.display().to_string(),
        message: e.to_string(),
    };
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io)? {
        out.push(entry.map_err(io)?.path());
    }
    out.sort();
    Ok(out)
}

fn cedar_files(
    dir: &Path,
    read: impl Fn(&Path) -> Result<String, LoadError>,
) -> Result<Vec<(String, String)>, LoadError> {
    let mut out = Vec::new();
    for p in sorted_entries(dir)? {
        if p.is_file() && p.extension().is_some_and(|e| e == "cedar") {
            out.push((file_name(&p), read(&p)?));
        }
    }
    Ok(out)
}

/// Why a bundle did not load. Variants carry file names and policy ids, not
/// Cedar's message text, so they stay stable across Cedar upgrades.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// A file could not be read.
    Io {
        /// The path.
        path: String,
        /// The OS error.
        message: String,
    },
    /// The schema did not parse.
    Schema,
    /// A policy file did not parse.
    Parse {
        /// The file.
        file: String,
    },
    /// A policy file holds a template; templates are not supported.
    Template {
        /// The file.
        file: String,
    },
    /// A policy has no `@id` annotation.
    MissingId {
        /// The file.
        file: String,
    },
    /// Two policies have the same `@id`.
    DuplicateId {
        /// The id.
        id: String,
    },
    /// A policy `@id` uses the reserved `damavand.` prefix.
    ReservedId {
        /// The id.
        id: String,
    },
    /// `@outcome` is not `"ask"`, or is on a permit.
    BadOutcome {
        /// The policy id.
        id: String,
    },
    /// A project policy is not scoped `resource in Project::"<id>"`.
    ProjectScope {
        /// The project directory.
        project: String,
        /// The policy id.
        id: String,
    },
    /// Strict validation against the schema failed for these policies.
    Validation {
        /// The policy ids, sorted.
        ids: Vec<String>,
    },
    /// An action is in no class group or in more than one, a class group is
    /// in another class group, or a `class:` group name is unknown.
    ActionClass {
        /// The action id.
        action: String,
    },
    /// A built-in Never action is in a class other than `class:never`.
    NeverReclassified {
        /// The action id.
        action: String,
    },
    /// An action's context type does not accept the engine's context record.
    ContextShape {
        /// The action id.
        action: String,
    },
    /// `autonomy.toml` is invalid.
    Autonomy {
        /// What is wrong.
        message: String,
    },
    /// An action id is not `[a-z][a-z0-9_.]*`.
    ActionId {
        /// The action id.
        action: String,
    },
    /// A permit names a Never action or `class:never` in its action scope.
    PermitsNever {
        /// The policy id.
        id: String,
    },
    /// `constraints.toml` is invalid: syntax, an unknown action, or an entry
    /// that is not exactly one non-empty `enum` or one `pattern`.
    Constraints {
        /// What is wrong.
        message: String,
    },
    /// A constraint pattern does not compile, is too long, or exceeds the
    /// size limits.
    PatternInvalid {
        /// The action.
        action: String,
        /// The parameter.
        param: String,
    },
    /// A constraint pattern can match a character in Unicode category `Cc`,
    /// `Cf`, `Zl` or `Zp` (controls, format characters such as bidi controls
    /// and zero-width joiners, line and paragraph separators) or a shell
    /// metacharacter, so it would clear arbitrary text. `\w` is refused: it
    /// admits U+200C and U+200D; spell the range out, as `[a-z0-9_]`.
    PatternTooBroad {
        /// The action.
        action: String,
        /// The parameter.
        param: String,
    },
    /// A constraint pattern matches the empty string, so it would clear an
    /// empty value.
    PatternMatchesEmpty {
        /// The action.
        action: String,
        /// The parameter.
        param: String,
    },
    /// `approval.toml` is invalid, or the max grant TTL is 0.
    Approval {
        /// What is wrong.
        message: String,
    },
    /// A broker key is not a valid Ed25519 public key, or is a weak key.
    BrokerKey {
        /// Position in the key list.
        index: usize,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io { path, message } => write!(f, "cannot read {path}: {message}"),
            LoadError::Schema => write!(f, "schema.cedarschema does not parse"),
            LoadError::Parse { file } => write!(f, "{file}: policy does not parse"),
            LoadError::Template { file } => write!(f, "{file}: templates are not supported"),
            LoadError::MissingId { file } => write!(f, "{file}: policy has no @id"),
            LoadError::DuplicateId { id } => write!(f, "duplicate policy @id {id:?}"),
            LoadError::ReservedId { id } => {
                write!(f, "policy @id {id:?} uses the reserved damavand. prefix")
            }
            LoadError::BadOutcome { id } => {
                write!(f, "policy {id:?}: @outcome must be \"ask\" on a forbid")
            }
            LoadError::ProjectScope { project, id } => {
                write!(
                    f,
                    "policy {id:?} in project {project:?} is not scoped to Project::{project:?}"
                )
            }
            LoadError::Validation { ids } => {
                write!(f, "strict validation failed: {}", ids.join(", "))
            }
            LoadError::ActionClass { action } => {
                write!(f, "action {action:?} is not in exactly one class group")
            }
            LoadError::NeverReclassified { action } => {
                write!(f, "action {action:?} must be in class:never")
            }
            LoadError::ContextShape { action } => {
                write!(
                    f,
                    "action {action:?}: context type does not match the engine context"
                )
            }
            LoadError::Autonomy { message } => write!(f, "autonomy.toml: {message}"),
            LoadError::ActionId { action } => {
                write!(f, "action id {action:?} is not [a-z][a-z0-9_.]*")
            }
            LoadError::PermitsNever { id } => {
                write!(f, "policy {id:?} permits a Never action")
            }
            LoadError::Constraints { message } => write!(f, "constraints.toml: {message}"),
            LoadError::PatternInvalid { action, param } => {
                write!(f, "constraint {action}.{param}: pattern is invalid")
            }
            LoadError::PatternTooBroad { action, param } => {
                write!(f, "constraint {action}.{param}: pattern is too broad")
            }
            LoadError::PatternMatchesEmpty { action, param } => {
                write!(
                    f,
                    "constraint {action}.{param}: pattern matches the empty string"
                )
            }
            LoadError::Approval { message } => write!(f, "approval.toml: {message}"),
            LoadError::BrokerKey { index } => write!(f, "broker key {index} is not valid"),
        }
    }
}

impl std::error::Error for LoadError {}
