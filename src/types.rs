use super::constants;
use jws::JsonObject;
use serde::Deserialize;
use serde_json;
use std;
use std::error::Error;

#[derive(Clone)]
pub enum LogLevel {
    Trace = 10,
    Debug = 20,
    Info = 30,
    Warning = 40,
    Error = 50,
    Fatal = 60,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Trace
    }
}

#[derive(Default)]
pub struct StrategyOptions {
    pub allow_multi_audiences: bool,
    pub audience: Vec<String>,
    pub client_id: String,
    pub clock_skew: u32,
    pub identity_metadata: String,
    pub ignore_expiration: bool,
    pub is_b2c: bool,
    pub is_common_endpoint: bool,
    pub issuer: Vec<String>,
    pub log_level: LogLevel,
    pub policy_name: String,
    pub scope: Vec<String>,
    pub validate_issuer: bool,
}

impl StrategyOptions {
    pub fn new() -> Self {
        Self {
            clock_skew: constants::CLOCK_SKEW,
            validate_issuer: true,
            ..Default::default()
        }
    }
}

pub trait Strategy {
    fn name(&self) -> String;
    fn options(&self) -> &StrategyOptions;
}

#[derive(Deserialize)]
pub struct Header {
    /// algorithm
    pub alg: String,
    /// key id
    pub kid: String,
    /// token type (e.g RS256, HS256)
    pub typ: String,
}

impl Header {
    pub fn from_json(header: &JsonObject) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            alg: header.get("alg").unwrap().as_str().unwrap().to_string(),
            kid: header.get("kid").unwrap().as_str().unwrap().to_string(),
            typ: header.get("typ").unwrap().as_str().unwrap().to_string(),
        })
    }
}

#[derive(Deserialize, Clone)]
pub struct Payload {
    /// audience
    pub aud: String,
    /// issuer
    pub iss: String,
    /// issued at (timestamp)
    pub iat: u32,
    /// not before (timestamp)
    pub nbf: u32,
    /// expiration (timestamp)
    pub exp: u32,
    pub aio: String,
    pub azp: String,
    pub azpacr: String,
    pub email: String,
    pub name: String,
    pub oid: String,
    pub preferred_username: String,
    pub rh: String,
    /// scope
    pub scp: String,
    /// subject
    pub sub: String,
    pub tid: String,
    /// username
    pub upn: String,
    pub uti: String,
    /// access token version
    pub ver: String,
}

impl Payload {
    pub fn from_message(message: &[u8]) -> Result<Self, Box<dyn Error>> {
        if let Ok(s) = std::str::from_utf8(message) {
            if let Ok(jwt_payload) = serde_json::from_str::<Payload>(s) {
                return Ok(jwt_payload);
            }
        }
        Err("No valid payload was provided".into())
    }
}

pub struct Signature {
    // exponent
    pub e: String,
    /// key type (f.ex. RSA)
    pub kty: String,
    /// modulus
    pub n: String,
}

pub struct Token {
    pub header: Header,
    pub payload: Payload,
    pub signature: Signature,
}
