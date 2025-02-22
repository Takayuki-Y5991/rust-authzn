use std::collections::HashMap;
use std::time::Duration;

use rust_authzn::{
  adapter::{
    inbound::authentication_adapter::{AuthenticationAdapter, RedirectUrlApiResponse},
    outbound::{okka_adapter::OkkaOAuthProvider, redis_adapter::RedisCacheAdapter},
  },
  config::route::create_router,
  core::usecase::authentication::AuthenticationUseCase,
};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::common::test_env::{setup_test_containers, TestContainers};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_generate_uri() {
  // Setup test environment with detailed logging
  println!("=== Starting test: test_generate_uri ===");

  // Start test containers with super extended timeout (5 minutes)
  println!("Starting test containers...");
  let containers = match timeout(Duration::from_secs(300), setup_test_containers()).await {
    Ok(result) => match result {
      Ok(containers) => {
        println!("✓ Containers started successfully");
        containers
      }
      Err(e) => {
        println!("✗ Container setup failed with error: {:?}", e);
        panic!("Failed to start test containers: {:?}", e);
      }
    },
    Err(_) => {
      println!("✗ Container startup timed out after 5 minutes");
      println!("Debugging suggestions:");
      println!("1. Check Docker logs for any issues");
      println!("2. Try pulling the containers manually before testing");
      println!("3. Increase system resources allocated to Docker");
      panic!("Timed out waiting for containers to start after 5 minutes");
    }
  };

  // Log container information
  println!("Redis URL: {}", &containers.redis_url);
  println!("OAuth URL: {}", &containers.oauth_url);

  // Start test server with better retry mechanism
  println!("Starting test server...");
  let server_result = start_test_server_with_retry(containers).await;

  let (address, containers) = server_result;
  println!("✓ Test server started at {}", &address);

  // Create HTTP client with reasonable timeout
  let client =
    reqwest::Client::builder().timeout(Duration::from_secs(20)).build().expect("Failed to build HTTP client");

  // Prepare test request
  let mut request_body = HashMap::new();
  request_body.insert("action", "Login");
  request_body.insert(
    "code_challenge",
    "test_code_challenge_with_minimum_length_of_43_characters_xxx",
  );
  request_body.insert("redirect_uri", "http://localhost:3000/callback");

  // Send request with timeout and retry
  println!("Sending test request to {}/auth/redirect", address);
  let response = send_request_with_retry(&client, &format!("{}/auth/redirect", address), &request_body).await;

  // Validate response
  println!("Response status: {}", response.status());
  assert!(
    response.status().is_success(),
    "Expected success status, got {}",
    response.status()
  );

  // Extract and validate cookie header
  let cookie_header = match response.headers().get("set-cookie") {
    Some(header) => {
      println!("✓ Set-Cookie header found");
      header.clone()
    }
    None => {
      println!("✗ Set-Cookie header not found");
      panic!("Set-Cookie header not found in response");
    }
  };

  // Parse and validate response body
  let response_body: RedirectUrlApiResponse = match response.json().await {
    Ok(body) => {
      println!("✓ Response body parsed successfully");
      body
    }
    Err(e) => {
      println!("✗ Failed to parse response body: {:?}", e);
      panic!("Failed to parse response: {:?}", e);
    }
  };

  // Validate response body fields
  assert!(
    !response_body.redirect_uri.is_empty(),
    "redirect_uri should not be empty"
  );
  assert!(!response_body.state.is_empty(), "state should not be empty");
  assert_eq!(response_body.expires_in, 600, "expires_in should be 600");
  println!("✓ Response body fields validated");

  // Validate redirect URI parameters
  assert!(
    response_body.redirect_uri.contains("response_type=code"),
    "redirect_uri should contain response_type=code"
  );
  assert!(
    response_body.redirect_uri.contains("client_id="),
    "redirect_uri should contain client_id"
  );
  assert!(
    response_body.redirect_uri.contains("redirect_uri="),
    "redirect_uri should contain redirect_uri"
  );
  assert!(
    response_body.redirect_uri.contains("state="),
    "redirect_uri should contain state"
  );
  println!("✓ Redirect URI parameters validated");

  // Validate cookie header content
  let cookie_str = cookie_header.to_str().unwrap();
  assert!(cookie_str.contains("auth_state="), "Cookie should contain auth_state");
  assert!(cookie_str.contains("Secure"), "Cookie should have Secure flag");
  assert!(cookie_str.contains("HttpOnly"), "Cookie should have HttpOnly flag");
  println!("✓ Cookie header validated");

  // Clean up containers with timeout
  println!("Cleaning up test containers...");
  match timeout(Duration::from_secs(30), containers.cleanup()).await {
    Ok(result) => match result {
      Ok(_) => println!("✓ Containers cleaned up successfully"),
      Err(e) => println!("Warning: Failed to clean up containers: {:?}", e),
    },
    Err(_) => println!("Warning: Container cleanup timed out"),
  }

  println!("=== Test completed successfully ===");
}

// Helper function for starting test server with retry logic
async fn start_test_server_with_retry(containers: TestContainers) -> (String, TestContainers) {
  const MAX_RETRIES: usize = 5;

  for attempt in 1..=MAX_RETRIES {
    match timeout(Duration::from_secs(15), spawn_app(containers)).await {
      Ok(result) => {
        println!("✓ Server started successfully on attempt {}", attempt);
        return result;
      }
      Err(_) => {
        panic!(
          "Server startup attempt {} timed out. No retry available because TestContainers is not Clone.",
          attempt
        );
      }
    }
  }

  panic!("Server startup failed after all retry attempts");
}

// Helper function for sending requests with retry logic
async fn send_request_with_retry(client: &reqwest::Client, url: &str, body: &HashMap<&str, &str>) -> reqwest::Response {
  const MAX_RETRIES: usize = 3;

  for attempt in 1..=MAX_RETRIES {
    match timeout(Duration::from_secs(10), client.post(url).json(body).send()).await {
      Ok(Ok(response)) => {
        println!("✓ Request succeeded on attempt {}", attempt);
        return response;
      }
      Ok(Err(e)) => {
        println!("× Request attempt {} failed: {}", attempt, e);
        if attempt < MAX_RETRIES {
          let backoff = Duration::from_secs(2 * attempt as u64);
          println!("Retrying in {} seconds...", backoff.as_secs());
          tokio::time::sleep(backoff).await;
        } else {
          panic!("Request failed after {} attempts: {}", MAX_RETRIES, e);
        }
      }
      Err(_) => {
        println!("× Request attempt {} timed out", attempt);
        if attempt < MAX_RETRIES {
          println!("Retrying...");
          tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
          panic!("Request timed out after {} attempts", MAX_RETRIES);
        }
      }
    }
  }

  panic!("Request failed after all retry attempts");
}

// Modified spawn_app function to accept containers
async fn spawn_app(containers: TestContainers) -> (String, TestContainers) {
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind random port");
  let port = listener.local_addr().unwrap().port();

  // Initialize OAuth provider with retry logic for connection issues
  let oauth_provider = match create_oauth_provider_with_retry(&containers.oauth_url).await {
    Ok(provider) => provider,
    Err(e) => panic!("Failed to create OAuth provider after multiple retries: {}", e),
  };

  // Initialize Redis cache with retry logic
  let redis_cache = match create_redis_cache_with_retry(&containers.redis_url).await {
    Ok(cache) => cache,
    Err(e) => panic!("Failed to create Redis cache after multiple retries: {}", e),
  };

  let auth_usecase = AuthenticationUseCase::new(oauth_provider, redis_cache);
  let auth_adapter = AuthenticationAdapter::new(auth_usecase);
  let app = create_router(auth_adapter);

  let address = format!("http://127.0.0.1:{}", port);

  // Spawn the server in a separate task
  tokio::spawn(async move {
    axum::serve(listener, app).await.unwrap();
  });

  println!("Starting test server on {}", &address);
  // Wait for server to fully start with exponential backoff
  let mut wait_time = 500;
  for i in 1..=3 {
    tokio::time::sleep(Duration::from_millis(wait_time)).await;
    println!("Server warm-up wait {}/3 ({} ms)", i, wait_time);
    wait_time *= 2;
  }

  (address, containers)
}

// Helper to create OAuth provider with retry
async fn create_oauth_provider_with_retry(oauth_url: &str) -> Result<OkkaOAuthProvider, String> {
  const MAX_RETRIES: usize = 3;

  for attempt in 1..=MAX_RETRIES {
    match OkkaOAuthProvider::new(
      &format!("{}/oauth2/default/v1/authorize", oauth_url),
      &format!("{}/oauth2/default/v1/token", oauth_url),
      "test-client-id",
      Some("test-client-secret"),
      "http://localhost:3000/callback",
      "test-issuer",
    ) {
      Ok(provider) => {
        println!("OAuth provider created successfully on attempt {}", attempt);
        return Ok(provider);
      }
      Err(e) => {
        println!("OAuth provider creation failed on attempt {}: {}", attempt, e);
        if attempt < MAX_RETRIES {
          tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
          return Err(format!("Failed to create OAuth provider: {}", e));
        }
      }
    }
  }

  Err("Failed to create OAuth provider after all retry attempts".to_string())
}

// Helper to create Redis cache with retry
async fn create_redis_cache_with_retry(redis_url: &str) -> Result<RedisCacheAdapter, String> {
  const MAX_RETRIES: usize = 3;

  for attempt in 1..=MAX_RETRIES {
    match RedisCacheAdapter::new(redis_url, "test:") {
      Ok(cache) => {
        println!("Redis cache created successfully on attempt {}", attempt);
        return Ok(cache);
      }
      Err(e) => {
        println!("Redis cache creation failed on attempt {}: {}", attempt, e);
        if attempt < MAX_RETRIES {
          tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
          return Err(format!("Failed to create Redis cache: {}", e));
        }
      }
    }
  }

  Err("Failed to create Redis cache after all retry attempts".to_string())
}
