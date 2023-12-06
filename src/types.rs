use super::constants;
use jws::JsonObject;
use serde::Deserialize;
use serde_json;
use std;
use std::error::Error;

pub trait FromMsg<'a, T: Deserialize<'a> + Clone> {
    fn from_message(message: &'a [u8]) -> Result<T, Box<dyn Error>> {
        if let Ok(s) = std::str::from_utf8(message) {
            if let Ok(jwt_payload) = serde_json::from_str::<T>(s) {
                return Ok(jwt_payload);
            }
        }
        Err("No valid payload was provided".into())
    }
}

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
pub struct AccessHeader {
    /// algorithm
    pub alg: String,
    /// key id
    pub kid: String,
    /// token type (e.g RS256, HS256)
    pub typ: String,
}

impl AccessHeader {
    pub fn from_json(header: &JsonObject) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            alg: header.get("alg").unwrap().as_str().unwrap().to_string(),
            kid: header.get("kid").unwrap().as_str().unwrap().to_string(),
            typ: header.get("typ").unwrap().as_str().unwrap().to_string(),
        })
    }
}

#[derive(Deserialize)]
pub struct IdHeader {
    /// algorithm
    pub alg: String,
    /// key id
    pub kid: String,
    /// token type (e.g RS256, HS256)
    pub typ: String,
    pub x5t: String,
}

impl IdHeader {
    pub fn from_json(header: &JsonObject) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            alg: header.get("alg").unwrap().as_str().unwrap().to_string(),
            kid: header.get("kid").unwrap().as_str().unwrap().to_string(),
            typ: header.get("typ").unwrap().as_str().unwrap().to_string(),
            x5t: header.get("x5y").unwrap().as_str().unwrap().to_string(),
        })
    }
}

#[derive(Deserialize, Clone)]
pub struct IdPayload {
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
    pub acr: String,
    pub aio: String,
    pub amr: Vec<String>,
    pub appid: String,
    pub appidacr: String,
    pub email: String,
    pub family_name: String,
    pub given_name: String,
    pub ipaddr: String,
    pub name: String,
    pub oid: String,
    pub onprem_sid: String,
    pub rh: String,
    /// scope
    pub scp: String,
    /// subject
    pub sub: String,
    pub tid: String,
    pub unique_name: String,
    /// username
    pub upn: String,
    pub uti: String,
    /// access token version
    pub ver: String,
}

impl FromMsg<'_, IdPayload> for IdPayload {}

#[derive(Deserialize, Clone)]
pub struct AccessPayload {
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

impl FromMsg<'_, AccessPayload> for AccessPayload {}

pub struct Signature {
    // exponent
    pub e: String,
    /// key type (f.ex. RSA)
    pub kty: String,
    /// modulus
    pub n: String,
}

pub struct AccessToken {
    pub header: AccessHeader,
    pub payload: AccessPayload,
    pub signature: Signature,
}

pub struct IdToken {
    pub header: IdHeader,
    pub payload: IdPayload,
    pub signature: Signature,
}

pub enum Token {
    AccessToken(AccessToken),
    IdToken(IdToken),
}

pub enum Payload {
    AccessPayload(AccessPayload),
    IdPayload(IdPayload),
}
