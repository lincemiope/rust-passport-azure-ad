use jws::Result;
use jws::compact::{decode_unverified, DecodedMessage};

#[derive(Clone)]
pub struct JWTKey {
  pub kid: String,
  pub n: String,
  pub e: String
}

pub struct JWTHeader {
  pub typ: String,
  pub alg: String,
  pub kid: String
}

pub struct JWTPayload {
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

pub struct JWTSignature {
  pub e: String,
  /// key type (f.ex. RSA)
  pub kty: String,
  pub n: String
}
pub struct JWT {
  pub header: JWTHeader,
  pub payload: JWTPayload,
  pub signature: JWTSignature
}

/*
use jws::{JsonObject, JsonValue, Result};
use jws::compact::{decode_verify, encode_sign, decode_unverified, DecodedMessage};
use jws::hmac::{Hs512Signer, HmacVerifier};

fn encode_decode() -> jws::Result<()> {
  // Add custom header parameters.
  let mut header = JsonObject::new();
  header.insert(String::from("typ"), JsonValue::from("text/plain"));

  // Encode and sign the message.
  let encoded = encode_sign(header, b"payload", &Hs512Signer::new(b"secretkey"))?;

  // Decode and verify the message.
  let decoded = decode_verify(encoded.data().as_bytes(), &HmacVerifier::new(b"secretkey"))?;

  assert_eq!(decoded.payload, b"payload");
  assert_eq!(decoded.header.get("typ").and_then(|x| x.as_str()), Some("text/plain"));

  Ok(())
}
*/

pub fn decode(jwt_str: &str) -> Result<(DecodedMessage, Vec<u8>)> {
    let decoded = decode_unverified(jwt_str.as_bytes());

    decoded
}