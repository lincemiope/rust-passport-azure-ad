use std::error::Error;
use crate::constants;
use jws::JsonObject;
use serde::Deserialize;
use serde_json;
use std;

#[derive(Clone)]
pub enum LogLevel {
    Trace = 10,
    Debug = 20,
    Info = 30,
    Warning = 40,
    Error = 50,
    Fatal = 60,
}

#[derive(Clone)]
pub struct StrategyOptionsParams {
    pub clock_stew: Option<u32>,
    pub pass_req_to_cb: Option<bool>,
    pub validate_issuer: Option<bool>,
    pub allow_multi_audiences: Option<bool>,
    pub audience: Option<Vec<String>>,
    pub is_b2c: Option<bool>,
    pub policy_name: Option<String>,
    pub issuer: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub identity_metadata: Option<String>,
    pub scope: Option<Vec<String>>,
    pub log_level: Option<LogLevel>,
    pub logging_no_pii: Option<bool>
}

#[derive(Clone)]
pub struct StrategyOptions {
    pub clock_stew: u32,
    pub pass_req_to_cb: bool,
    pub validate_issuer: bool,
    pub allow_multi_audiences: bool,
    pub audience: Vec<String>,
    pub is_b2c: bool,
    pub policy_name: String,
    pub issuer: Vec<String>,
    pub client_id: String,
    pub identity_metadata: String,
    pub scope: Vec<String>,
    pub log_level: LogLevel,
    pub is_common_endpoint: bool,
    pub logging_no_pii: bool
}

impl StrategyOptions {
    pub fn new() -> Self {
        Self {
            clock_stew: constants::CLOCK_STEW,
            pass_req_to_cb: false,
            validate_issuer: false,
            allow_multi_audiences: false,
            audience: vec![],
            is_b2c: false,
            policy_name: String::new(),
            issuer: vec![],
            client_id: String::new(),
            identity_metadata: String::new(),
            scope: vec![],
            log_level: LogLevel::Debug,
            is_common_endpoint: false,
            logging_no_pii: false
        }
    }
}


pub trait Strategy {
    fn name(&self) -> String;

    fn options(&self) -> StrategyOptions;

    fn fail_with_log(&self, message: &str) -> Result<(), Box<dyn Error>> {
        println!("[ERROR] {}", message);
        Err(message.into())
    }
}

#[derive(Clone, Deserialize)]
pub struct OidcKey {
  pub kid: String,
  pub n: String,
  pub e: String,
  #[serde(alias = "use")]
  pub key_use: String,
  pub x5t: String,
  pub x5c: Vec<String>,
  pub issuer: String,
  pub kty: String
}


#[derive(Deserialize)]
pub struct Header {
  pub typ: String,
  pub alg: String,
  pub kid: String
}

impl Header {
  pub fn from_json(header: &JsonObject) -> Result<Self, Box<dyn Error>> {
      Ok(Self {
          typ: header.get("typ").unwrap().as_str().unwrap().to_string(),
          alg: header.get("alg").unwrap().as_str().unwrap().to_string(),
          kid: header.get("kid").unwrap().as_str().unwrap().to_string()
      })
  }
}

#[derive(Deserialize)]
pub struct Payload {
  /// audience
  pub aud: String,
  /// issuer
  pub iss: String,
  /// issued at (timestamp)
  pub iat: u32,
  /// nbf ? (timestamp)
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
  pub sub: String,
  pub tid: String,
  /// username
  pub upn: String,
  pub uti: String,
  /// access token version
  pub ver: String
}

impl Payload {
  pub fn from_message(message: &Vec<u8>) -> Result<Self, Box<dyn Error>> {
    if let Ok(s) = std::str::from_utf8(&message[..]) {
      if let Ok(jwt_payload) = serde_json::from_str::<Payload>(s) {
        return Ok(jwt_payload);
      }
    }
    return Err("No valid payload was provided".into());
  }
}

pub struct Signature {
  pub e: String,
  /// key type (f.ex. RSA)
  pub kty: String,
  pub n: String
}

pub struct Token {
  pub header: Header,
  pub payload: Payload,
  pub signature: Signature
}