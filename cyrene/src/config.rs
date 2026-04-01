use serde::{Deserialize, Serialize};

use crate::daemon::err::RunError;
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub controller: ControllerConfig,

    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ControllerConfig {
    pub urn: String,
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

pub fn read_cached_file() -> Result<DaemonConfig, RunError> {
    // TODO: take non-default path?
    
    // read initial configuration
    // 
    // the `runtime` section is generally overwritten upon communication
    // with a controller; though the previous runtime configuration is
    // cached between runs to allow for semi-autonomous operation.

    let config_file = fs::read_to_string("./priv/config.toml")?;

    let config = toml::from_str::<DaemonConfig>(&config_file)
        .map_err(|e| RunError::Config(format!("err: {e:?}")))?;

    Ok(config)
}
