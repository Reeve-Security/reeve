use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub root: PathBuf,
    pub description: String,
}

impl Target {
    pub fn filesystem(root: PathBuf) -> Self {
        let description = root.display().to_string();
        Self { root, description }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolProvider {
    pub surface: String,
    pub name: String,
    pub transport: Transport,
    #[serde(default)]
    pub source_path: Option<PathBuf>,
    #[serde(default)]
    pub discovery_source: DiscoverySource,
    #[serde(default)]
    pub extension: Option<ExtensionMetadata>,
    #[serde(default)]
    pub declared_tools: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoverySource {
    #[default]
    BuiltIn,
    UserDefined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionMetadata {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub install_root: Option<PathBuf>,
    #[serde(default)]
    pub signature_status: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Transport {
    Stdio(StdioConfig),
    HttpSse(HttpConfig),
    WebSocket(WsConfig),
    Unknown(UnknownConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioConfig {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpConfig {
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub tls_leaf_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsConfig {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownConfig {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderIdentity {
    pub bom_ref: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub entry_point: Option<PathBuf>,
    #[serde(default)]
    pub entry_point_sha256: Option<String>,
    #[serde(default)]
    pub published_artifact_sha256: Option<String>,
    #[serde(default)]
    pub published_artifact_reason: Option<String>,
    #[serde(default)]
    pub sigstore_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub declared: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorProfile {
    #[serde(default)]
    pub observed: Vec<Capability>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProfileOptions {
    #[serde(default)]
    pub timeout_per_tool_seconds: u64,
    #[serde(default)]
    pub timeout_total_seconds: u64,
    #[serde(default)]
    pub scan_id: String,
    #[serde(default)]
    pub evidence_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub qualifiers: Map<String, Value>,
    pub source: CapabilitySource,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilitySource {
    Declared,
    Observed,
    Granted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: String,
    pub kind: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub id: String,
    pub policy_id: String,
    #[serde(default)]
    pub bom_ref: Option<String>,
    pub status: PolicyStatus,
    pub justification: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    Allow,
    Deny,
    Warn,
}

#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    async fn discover(&self, target: &Target) -> anyhow::Result<Vec<ToolProvider>>;
    async fn fingerprint(&self, provider: &ToolProvider) -> anyhow::Result<ProviderIdentity>;
    async fn introspect(&self, provider: &ToolProvider) -> anyhow::Result<Capabilities>;
    async fn profile(
        &self,
        provider: &ToolProvider,
        opts: &ProfileOptions,
    ) -> anyhow::Result<BehaviorProfile>;
}
