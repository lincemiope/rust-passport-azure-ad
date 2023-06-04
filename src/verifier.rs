use std::{error::Error};
use jws::compact::decode_unverified;

extern crate alcoholic_jwt;
use alcoholic_jwt::{Validation, validate, token_kid};
use crate::{types::{Strategy, Payload}};
use super::metadata::MetadataHandler;

pub async fn verify(jwt_string: String, metadata: &MetadataHandler, strategy: &dyn Strategy) -> Result<Payload, Box<dyn Error>> {
    let s_opts = &strategy.options();

    if s_opts.audience.is_empty() {
        return Err("In verifier.verify: audience is not valid".into());
    }

    if metadata.oidc.algorithms.is_empty() {
        return Err("In verifier.verify: algorithms is not valid".into());
    }

    let parts: Vec<&str> = jwt_string.split(".").collect();

    if parts.len() != 3 {
        return Err("In verifier.verify: jwt_string is malformet".into());
    }

    if parts[2].is_empty() {
        return Err("In verifier.verify: signature is missing in jwt_string".into());
    }

    let decoded = decode_unverified(jwt_string.clone().as_bytes()).unwrap();
    let payload = Payload::from_message(&decoded.0.payload).unwrap();

    // Several types of built-in validations are provided:
    let validations = vec![
        Validation::Issuer(strategy.options().issuer[0].clone()),
        Validation::SubjectPresent
    ];

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(&jwt_string)
        .expect("In verifier.verify: failed to decode token headers")
        .expect("In verifier.verify: no 'kid' claim present in token");

    if let Some(jwks) = &metadata.jwks {
        let jwk = jwks.find(&kid)
            .expect("In verifier.verify: specified key not found in set");

        if let Ok(valid) = validate(&jwt_string, jwk, validations) {
            let scopes: Vec<String> = valid.claims
                .as_object()
                .unwrap()
                .get("scp")
                .unwrap()
                .as_array()
                .unwrap()
                .into_iter()
                .map(|e| e.to_string())
                .collect();
            if !scopes.contains(&payload.scp) {
                return Err("In verifier.verify: token scopes are not valid".into());
            }
            return Ok(payload)
        } else {
            return Err("In verifier.verify: token validation has failed!".into());
        }
    } else {
        return Err("In verifier.verify: no JWKS are present".into());
    }
}