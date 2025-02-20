use std::sync::Arc;

use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, AsyncCommands, Client, RedisError};
use serde::{de::DeserializeOwned, Serialize};

use crate::port::outbound::cache_provider::CacheProvider;

#[derive(Clone)]
pub struct RedisCacheAdapter {
  client: Arc<Client>,
  prefix: String,
}

impl RedisCacheAdapter {
  pub fn new(redis_url: &str, prefix: &str) -> Result<Self, RedisError> {
    let client = Client::open(redis_url)?;
    Ok(Self {
      client: Arc::new(client),
      prefix: prefix.to_string(),
    })
  }
  fn prefixed_key(&self, key: &str) -> String {
    format!("{}{}", self.prefix, key)
  }

  async fn get_connection(&self) -> Result<MultiplexedConnection, RedisError> {
    self.client.get_multiplexed_async_connection().await
  }
}

#[async_trait]
impl CacheProvider for RedisCacheAdapter {
  async fn store<T: Serialize + Send + Sync>(
    &self,
    key: &str,
    data: &T,
    ttl: u64,
  ) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = self.get_connection().await?;

    let prefix_key = self.prefixed_key(key);
    let serialized = serde_json::to_string(data)?;

    let _: () = conn.set_ex(prefix_key, serialized, ttl).await?;

    Ok(())
  }

  async fn get<T: DeserializeOwned + Send + Sync>(&self, key: &str) -> Result<Option<T>, Box<dyn std::error::Error>> {
    let mut conn = self.get_connection().await?;

    let prefix_key = self.prefixed_key(key);
    let data: Option<String> = conn.get(prefix_key).await?;

    match data {
      Some(json_str) => {
        let deserialized = serde_json::from_str(&json_str)?;
        Ok(Some(deserialized))
      }
      None => Ok(None),
    }
  }

  async fn remove(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = self.get_connection().await?;

    let prefix_key = self.prefixed_key(key);
    let _: () = conn.del(prefix_key).await?;

    Ok(())
  }
}
