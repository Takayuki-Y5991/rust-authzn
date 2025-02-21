use std::env;

#[derive(Clone, Debug)]
pub struct Config {
  pub server: ServerConfig,
  pub oauth: OAuthConfig,
  pub redis: RedisConfig,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
  pub host: String,
  pub port: u16,
}

#[derive(Clone, Debug)]
pub struct OAuthConfig {
  pub client_id: String,
  pub client_secret: String,
  pub auth_url: String,
  pub token_url: String,
  pub redirect_url: String,
  pub userinfo_url: String,
}

#[derive(Clone, Debug)]
pub struct RedisConfig {
  pub url: String,
  pub prefix: String,
}

impl Config {
  pub fn from_env() -> Self {
    dotenvy::dotenv().ok();

    let server = ServerConfig {
      host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
      port: env::var("SERVER_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("Failed to parse SERVER_PORT"),
    };

    let oauth = OAuthConfig {
      client_id: env::var("OAUTH_CLIENT_ID").expect("OAUTH_CLIENT_ID must be set"),
      client_secret: env::var("OAUTH_CLIENT_SECRET").expect("OAUTH_CLIENT_SECRET must be set"),
      auth_url: env::var("OAUTH_AUTH_URL").expect("OAUTH_AUTH_URL must be set"),
      token_url: env::var("OAUTH_TOKEN_URL").expect("OAUTH_TOKEN_URL must be set"),
      redirect_url: env::var("OAUTH_REDIRECT_URL").expect("OAUTH_REDIRECT_URL must be set"),
      userinfo_url: env::var("OAUTH_USERINFO_URL").expect("OAUTH_USERINFO_URL must be set"),
    };

    let redis = RedisConfig {
      url: env::var("REDIS_URL").expect("REDIS_URL must be set"),
      prefix: env::var("REDIS_PREFIX").expect("REDIS_PREFIX must be set"),
    };

    Config { server, oauth, redis }
  }
}
