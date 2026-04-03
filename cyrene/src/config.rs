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

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;
    use super::DaemonConfig;

    mod fixture {
        const CFG_CONTROLLER: &str = r#"
        [controller]
        urn = "127.0.0.1:4001"
        pubkey = "G1miu0MO4OpECY5Hl17TazqJKJOTtQc59dpfJQhwPlE="
        privkey = "kexg23McVMQJXjqk9yi3w64vfdVOWvUZCpp0CiOsXbA="
        "#;

        const CFG_RUNTIMES: &str = r#"
        [[runtime.datasets]]
        name = "nico/users"
        snap_prefix = "snapcon"
        snap_interval = 600
        matchspec = "1x1h(keep=all)"

        [[runtime.datasets]]
        name = "nico/media"
        snap_prefix = "snapcon"
        snap_interval = 600
        matchspec = "1x1h(keep=all)"
        "#;

        pub fn controller_only() -> String {
            format!("{}", CFG_CONTROLLER)
        }

        pub fn runtime_only() -> String {
            format!("{}", CFG_RUNTIMES)
        }

        pub fn full_config() -> String {
            format!("{}\n{}", CFG_CONTROLLER, CFG_RUNTIMES)
        }
    }

    #[test]
    fn test_minimal_file() {

        let parsed = toml::from_str::<DaemonConfig>(&fixture::controller_only())
            .expect("could not parse example");

        assert!(parsed.controller.urn.len() > 0);
        assert!(parsed.runtime.is_none());

        BASE64.decode(parsed.controller.pubkey.as_bytes())
            .expect("not base64 key");

        BASE64.decode(parsed.controller.privkey.as_bytes())
            .expect("not base64 key");
    }

    #[test]
    #[should_panic = "not parse"]
    fn test_missing_controller() {
        let _parsed = toml::from_str::<DaemonConfig>(&fixture::runtime_only())
            .expect("could not parse example");
    }

    #[test]
    fn test_runtime_len() {
        let parsed = toml::from_str::<DaemonConfig>(&fixture::full_config())
            .expect("could not parse example");

        let runtime = parsed.runtime.expect("no runtime blocks?");
        assert_eq!(2, runtime.datasets.len());
    }
}
