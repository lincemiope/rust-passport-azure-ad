use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub struct PassportError {
    source: String,
    message: String,
}

impl From<(String, String)> for PassportError {
    fn from(value: (String, String)) -> Self {
        Self {
            source: value.0,
            message: value.1,
        }
    }
}

impl Display for PassportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "In {}: {}", self.source, self.message)
    }
}

impl Error for PassportError {}
