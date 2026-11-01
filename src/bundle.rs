//! Policy bundles: the files the engine loads.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::types::BundleId;

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
/// global/*.cedar
/// projects/<id>/*.cedar
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub(crate) id: BundleId,
    pub(crate) schema: String,
    pub(crate) global: Vec<PolicyFile>,
    pub(crate) projects: BTreeMap<String, Vec<PolicyFile>>,
    pub(crate) autonomy: String,
}

impl Bundle {
    /// A bundle with a schema and no policies or caps.
    pub fn new(id: BundleId, schema: impl Into<String>) -> Self {
        Self {
            id,
            schema: schema.into(),
            global: Vec::new(),
            projects: BTreeMap::new(),
            autonomy: String::new(),
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

    /// The bundle id.
    pub fn id(&self) -> &BundleId {
        &self.id
    }

    /// Read a bundle directory. `id` is the commit sha of the checkout.
    /// Files are read in name order.
    pub fn from_dir(dir: &Path, id: BundleId) -> Result<Bundle, LoadError> {
        let read = |p: &Path| {
            std::fs::read_to_string(p).map_err(|e| LoadError::Io {
                path: p.display().to_string(),
                message: e.to_string(),
            })
        };
        let schema = read(&dir.join("schema.cedarschema"))?;
        let autonomy_path = dir.join("autonomy.toml");
        let autonomy = if autonomy_path.exists() {
            read(&autonomy_path)?
        } else {
            String::new()
        };
        let mut bundle = Bundle::new(id, schema).with_autonomy(autonomy);
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
        }
    }
}

impl std::error::Error for LoadError {}
