use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub controller: ControllerConfig,

    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ControllerConfig {
    pub url: String,
    pub pubkey: String,
    pub privkey: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub datasets: Vec<DatasetConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DatasetConfig {
    pub name: String,
    pub snap_prefix: String,
    pub snap_interval: u32,
    pub matchspec: String,
}
