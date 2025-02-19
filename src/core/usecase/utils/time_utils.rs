use std::sync::{LazyLock, Mutex};

static MOCK_TIME: LazyLock<Mutex<Option<u64>>> = LazyLock::new(|| Mutex::new(None));

pub fn now_time_secs() -> Result<u64, Box<dyn std::error::Error>> {
  // モック時間が設定されていれば使用
  if let Some(mock_time) = *MOCK_TIME.lock().unwrap() {
    return Ok(mock_time);
  }

  let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_err(|e| format!("System time error: {}", e))?
    .as_secs();
  Ok(now)
}

#[cfg(test)]
pub mod test_utils {
  use super::*;

  pub fn set_mock_time(seconds: u64) {
    let mut mock = MOCK_TIME.lock().unwrap();
    *mock = Some(seconds);
  }

  pub fn reset_mock_time() {
    let mut mock = MOCK_TIME.lock().unwrap();
    *mock = None;
  }
}
