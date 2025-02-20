use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

#[async_trait]
pub trait CacheProvider {
  async fn store<T: Serialize + Send + Sync>(
    &self,
    key: &str,
    data: &T,
    ttl: u64,
  ) -> Result<(), Box<dyn std::error::Error>>;
  async fn get<T: DeserializeOwned + Send + Sync>(&self, key: &str) -> Result<Option<T>, Box<dyn std::error::Error>>;
  async fn remove(&self, key: &str) -> Result<(), Box<dyn std::error::Error>>;
}
