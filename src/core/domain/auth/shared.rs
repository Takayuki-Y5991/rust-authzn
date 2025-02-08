#[derive(Debug, Clone, PartialEq)]
pub struct Scopes(Vec<String>);

impl Scopes {
    pub fn new(scopes: Vec<String>) -> Result<Self, AuthError> {
        Ok(Self(scopes))
    }

    pub fn contains_all(&self, other: &Scopes) -> bool {
        other.0.iter().all(|scope| self.0.contains(scope))
    }
}