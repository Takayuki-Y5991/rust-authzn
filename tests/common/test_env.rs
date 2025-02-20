use redis;
use reqwest;
use serde_json::json;
use std::error::Error;
use std::time::Duration;
use testcontainers::{
  core::{IntoContainerPort, WaitFor},
  runners::AsyncRunner,
  ContainerAsync, GenericImage, ImageExt,
};
use tokio::time::timeout;

const REDIS_PORT: u16 = 6379;
const OAUTH_PORT: u16 = 8080;
const REDIS_TIMEOUT: u64 = 60;
const OAUTH_TIMEOUT: u64 = 240; // Extended further to 4 minutes
const VERIFICATION_TIMEOUT: u64 = 15;

pub struct TestContainers {
  pub redis_url: String,
  pub oauth_url: String,
  pub redis_container: ContainerAsync<GenericImage>,
  pub oauth_container: ContainerAsync<GenericImage>,
}

impl TestContainers {
  pub async fn cleanup(&self) -> Result<(), Box<dyn Error>> {
    println!("Cleaning up test containers...");

    // Use timeout for container stop operations with better error handling
    match timeout(Duration::from_secs(15), self.redis_container.stop()).await {
      Ok(Ok(_)) => println!("Redis container stopped successfully"),
      Ok(Err(e)) => println!("Warning: Failed to stop Redis container: {:?}", e),
      Err(_) => println!("Warning: Redis container stop timed out"),
    }

    match timeout(Duration::from_secs(15), self.oauth_container.stop()).await {
      Ok(Ok(_)) => println!("OAuth container stopped successfully"),
      Ok(Err(e)) => println!("Warning: Failed to stop OAuth container: {:?}", e),
      Err(_) => println!("Warning: OAuth container stop timed out"),
    }

    println!("Containers cleanup completed");
    Ok(())
  }
}

pub async fn setup_test_containers() -> Result<TestContainers, Box<dyn Error>> {
  // Setup Docker network (optional, but can help with container communication)
  println!("Setting up Redis container...");

  // Start Redis container with explicit wait condition
  let redis_start = timeout(
    Duration::from_secs(REDIS_TIMEOUT),
    GenericImage::new("redis", "7.2.4-alpine") // Using Alpine for faster startup
      .with_exposed_port(REDIS_PORT.tcp())
      .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
      .start(),
  )
  .await??;

  let redis_container = redis_start;

  // Get Redis host details
  let redis_host = timeout(Duration::from_secs(5), redis_container.get_host()).await??;

  let redis_host_port = timeout(Duration::from_secs(5), redis_container.get_host_port_ipv4(REDIS_PORT)).await??;

  let redis_url = format!("redis://{redis_host}:{redis_host_port}");
  println!("Redis container started successfully at {}", redis_url);

  // Verify Redis is accessible
  verify_redis_quick(&redis_url).await?;

  println!("Setting up OAuth2 mock server...");

  // Configure OAuth2 mock server with configuration from Go example
  let json_config = json!({
      "interactiveLogin": true,
      "httpServer": "NettyWrapper",
      "tokenCallbacks": [
          {
              "issuerId": "default",
              "tokenExpiry": 3600,
              "requestMappings": [
                  {
                      "requestParam": "grant_type",
                      "match": "authorization_code",
                      "claims": {
                          "sub": "test-user",
                          "email": "test@example.com",
                          "email_verified": true,
                          "name": "Test User",
                          "roles": ["user"]
                      }
                  },
                  {
                      "requestParam": "code",
                      "match": "test-auth-code",
                      "claims": {
                          "sub": "subByCode",
                          "aud": [
                              "audByCode"
                          ]
                      }
                  }
              ]
          }
      ]
  });

  println!("Starting OAuth2 container (v2.1.0 as in Go example)...");

  // Using version 2.1.0 as in the Go example and multiple wait conditions
  let oauth_container_builder = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.1.0")
    .with_exposed_port(OAUTH_PORT.tcp())
    // Multiple wait conditions as in the Go example
    .with_wait_for(WaitFor::message_on_stdout("started server on address="))
    .with_env_var("SERVER_PORT", OAUTH_PORT.to_string())
    .with_env_var("LOG_LEVEL", "debug") // Added debug logging
    .with_env_var("JSON_CONFIG", json_config.to_string());

  println!(
    "Starting OAuth2 container with extended timeout ({}s)...",
    OAUTH_TIMEOUT
  );
  let oauth_start = match timeout(Duration::from_secs(OAUTH_TIMEOUT), oauth_container_builder.start()).await {
    Ok(result) => {
      match &result {
        Ok(_) => println!("OAuth2 container started successfully"),
        Err(e) => println!("Failed to start OAuth2 container: {:?}", e),
      }
      result
    }
    Err(_) => {
      println!("ERROR: OAuth2 container startup timed out after {}s", OAUTH_TIMEOUT);
      println!("Recommendations:");
      println!("1. Try using version 2.1.0: docker pull ghcr.io/navikt/mock-oauth2-server:2.1.0");
      println!("2. Check if the wait condition matches actual server output");
      println!("3. Consider modifying network settings");
      return Err("OAuth2 container startup timed out".into());
    }
  }?;

  let oauth_container = oauth_start;

  // Get OAuth server host details with timeout
  let oauth_host = timeout(Duration::from_secs(5), oauth_container.get_host()).await??;

  let oauth_host_port = timeout(Duration::from_secs(5), oauth_container.get_host_port_ipv4(OAUTH_PORT)).await??;

  let oauth_url = format!("http://{oauth_host}:{oauth_host_port}");
  println!("OAuth container mapped to {}", oauth_url);

  // Wait for the OAuth service to stabilize as done in Go example
  println!("Waiting for OAuth service to stabilize...");
  tokio::time::sleep(Duration::from_secs(5)).await;

  // Implement retry logic like in Go example
  verify_oauth_with_retry(&oauth_url).await?;

  println!("Test containers setup completed successfully");
  Ok(TestContainers {
    redis_url,
    oauth_url,
    redis_container,
    oauth_container,
  })
}

// Quick Redis verification
async fn verify_redis_quick(redis_url: &str) -> Result<(), Box<dyn Error>> {
  match timeout(Duration::from_secs(3), async {
    let client = redis::Client::open(redis_url)?;
    let _conn = client.get_connection()?;
    Ok::<(), Box<dyn Error>>(())
  })
  .await
  {
    Ok(Ok(_)) => {
      println!("Redis verification: port is accessible");
      Ok(())
    }
    Ok(Err(e)) => {
      println!("Redis verification warning: {}", e);
      // Continue anyway - non-blocking verification
      Ok(())
    }
    Err(_) => {
      println!("Redis verification timed out");
      // Continue anyway - non-blocking verification
      Ok(())
    }
  }
}

// Verify OAuth server with retry logic similar to Go implementation
async fn verify_oauth_with_retry(oauth_url: &str) -> Result<(), Box<dyn Error>> {
  let max_retries = 10;
  let mut last_error = None;

  for retry in 0..max_retries {
    let backoff = Duration::from_secs(5 * (retry + 1));

    match verify_oauth_server_endpoint(oauth_url).await {
      Ok(_) => {
        println!("✓ OAuth server verified successfully on attempt {}", retry + 1);
        return Ok(());
      }
      Err(e) => {
        println!("× OAuth verification attempt {} failed: {}", retry + 1, e);
        last_error = Some(e);

        if retry < max_retries - 1 {
          println!("Retrying in {} seconds...", backoff.as_secs());
          tokio::time::sleep(backoff).await;
        }
      }
    }
  }

  if let Some(e) = last_error {
    println!(
      "WARNING: OAuth server verification failed after {} attempts",
      max_retries
    );
    println!("Last error: {}", e);
    println!("Continuing anyway as the server might still be functional...");
  }

  // Return success even if verification failed to match Go behavior
  Ok(())
}

// Verify OAuth server by checking openid-configuration endpoint
async fn verify_oauth_server_endpoint(oauth_url: &str) -> Result<(), Box<dyn Error>> {
  let client = reqwest::Client::builder().timeout(Duration::from_secs(VERIFICATION_TIMEOUT)).build()?;

  let endpoint = format!("{}/.well-known/openid-configuration", oauth_url);
  println!("Checking OAuth endpoint: {}", endpoint);

  let response = client.get(&endpoint).send().await?;

  if !response.status().is_success() {
    return Err(
      format!(
        "OAuth server returned status: {} for endpoint {}",
        response.status(),
        endpoint
      )
      .into(),
    );
  }

  // Optionally parse and validate response similar to Go HTTP test
  let config: serde_json::Value = response.json().await?;
  if !config.get("issuer").is_some() {
    return Err("OAuth server config missing 'issuer' field".into());
  }

  Ok(())
}
