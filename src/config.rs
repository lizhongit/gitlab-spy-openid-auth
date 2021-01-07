use std::fs;
use std::error::Error;
use serde::{Serialize, Deserialize, de };

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Config {
  pub gitlab_url: String,
  pub iss_url: String,
}

impl Config {
  pub fn new<Config: 'static>(config_file: String) -> Result<Config, Box<dyn Error>>
  where
    Config: de::DeserializeOwned,
  {
    let config_content = fs::read_to_string(config_file)?;
    let config: Config = serde_yaml::from_str(&config_content.clone())?;

    Ok(config)
  }
}
