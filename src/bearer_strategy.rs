extern crate alcoholic_jwt;

use super::error::PassportError;
use super::metadata::MetadataHandler;
use super::types::Payload;
use super::{
    constants,
    types::{LogLevel, Strategy, StrategyOptions},
    util,
};
use alcoholic_jwt::{token_kid, validate, Validation};
use jws::compact::decode_unverified;
use regex::Regex;
use url::Url;

static BEARER_NAME: &str = "oauth-bearer";

pub struct BearerStrategy {
    name: String,
    options: StrategyOptions,
}

impl BearerStrategy {
    /// Builds BearerStrategy with all its options
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        allow_multi_audiences: Option<bool>,
        audience: Option<Vec<String>>,
        client_id: Option<String>,
        clock_skew: Option<u32>,
        identity_metadata: Option<String>,
        ignore_expiration: Option<bool>,
        is_b2c: Option<bool>,
        issuer: Option<Vec<String>>,
        log_level: Option<LogLevel>,
        policy_name: Option<String>,
        scope: Option<Vec<String>>,
        validate_issuer: Option<bool>,
    ) -> Result<Self, PassportError> {
        let mut options: StrategyOptions = StrategyOptions::new();

        // allow_multi_audiences
        if let Some(allow_multi_audiences_value) = allow_multi_audiences {
            options.allow_multi_audiences = allow_multi_audiences_value;
        }

        // client_id
        if let Some(client_id_value) = client_id {
            options.client_id = client_id_value;
        } else {
            return util::fail_with_log::<Self>(
                "BearerStrategy constructor",
                "'client_id' cannot be empty",
            );
        }

        // audience
        if let Some(audience_value) = audience {
            if audience_value.is_empty() {
                options.audience = vec![
                    options.client_id.clone(),
                    vec![String::from("spn:"), options.client_id.clone()].join(""),
                ];
            }
        }

        // clock_skew
        if let Some(clock_skew_value) = clock_skew {
            options.clock_skew = clock_skew_value;
        }

        // issuer
        if let Some(issuer_value) = issuer {
            options.issuer = issuer_value;
        }

        // ignore expiration
        if let Some(ignore_expiration_value) = ignore_expiration {
            options.ignore_expiration = ignore_expiration_value;
        }

        // log level
        if let Some(log_level_value) = log_level {
            options.log_level = log_level_value;
        }

        // identity_metadata
        if identity_metadata.is_none() {
            return util::fail_with_log::<Self>(
                "BearerStrategy constructor",
                "'identity_metadata' must be provided",
            );
        }

        let identity_metadata_value = identity_metadata.unwrap();

        let identity_metadata_parsed = Url::parse(identity_metadata_value.as_str());
        if identity_metadata_parsed.is_err()
            || identity_metadata_parsed.unwrap().scheme() != "https"
        {
            return util::fail_with_log::<Self>(
                "BearerStrategy constructor",
                "'identity_metadata' must be a valid https url",
            );
        }

        // check if we are using the common endpoint
        options.is_common_endpoint = identity_metadata_value.contains("/common/");
        options.identity_metadata = identity_metadata_value;

        // scope
        if let Some(scope_value) = scope {
            if scope_value.is_empty() {
                return util::fail_with_log::<Self>(
                    "BearerStrategy constructor",
                    "'scope' must be a non-empty array",
                );
            }
            options.scope = scope_value;
        }

        // policy_name
        if let Some(policy_name_value) = policy_name {
            options.policy_name = policy_name_value;
        }

        // is_b2c
        if let Some(is_b2c_value) = is_b2c {
            if is_b2c_value {
                let re = Regex::new(constants::POLICY_REGEX).unwrap();
                if !re.is_match(options.policy_name.as_str()) {
                    return util::fail_with_log::<Self>(
                        "BearerStrategy constructor",
                        "invalid policy for B2C",
                    );
                }
            }
        }

        // validate_issuer
        if let Some(validate_issuer_value) = validate_issuer {
            options.validate_issuer = validate_issuer_value;
        }

        Ok(Self::new(options))
    }

    fn new(options: StrategyOptions) -> Self {
        Self {
            name: String::from(BEARER_NAME),
            options,
        }
    }

    pub async fn jwt_verify(
        &self,
        token: String,
        handler: &mut MetadataHandler,
    ) -> Result<Payload, PassportError> {
        let metadata = handler.metadata().await.unwrap();
        let jwks = handler.jwks().await.unwrap();

        if metadata.id_token_signing_alg_values_supported.is_empty() {
            return util::fail_with_log::<Payload>(
                "BearerStrategy.verify",
                "'algorithms' is not valid",
            );
        }

        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() != 3 {
            return util::fail_with_log::<Payload>(
                "BearerStrategy.verify",
                "'jwt_string' is malformed",
            );
        }

        if parts[2].is_empty() {
            return util::fail_with_log::<Payload>(
                "BearerStrategy.verify",
                "signature is missing in 'jwt_string",
            );
        }

        let decoded = decode_unverified(token.clone().as_bytes()).unwrap();
        let payload = Payload::from_message(&decoded.0.payload).unwrap();

        // Several types of built-in validations are provided:
        let mut validations = vec![Validation::SubjectPresent];

        // ignore expiration
        if !self.options.ignore_expiration {
            validations.push(Validation::NotExpired);
        }

        // validate issuer
        if self.options.validate_issuer {
            validations.push(Validation::Issuer(self.options.issuer[0].clone()));
        }

        // If a JWKS contains multiple keys, the correct KID first
        // needs to be fetched from the token headers.
        let kid = token_kid(&token)
            .expect("In BearerStrategy.verify: failed to decode token headers")
            .expect("In BearerStrategy.verify: no 'kid' claim present in token");

        let jwk = jwks
            .find(&kid)
            .expect("In BearerStrategy.verify: specified key not found in set");

        if let Ok(valid) = validate(&token, jwk, validations) {
            // validate audience
            let token_audience: Vec<String> = util::extract_claim_vec(&valid.claims, "aud");

            // validate multiple audiences
            if !self.options.allow_multi_audiences && token_audience.len() > 1usize {
                return util::fail_with_log::<Payload>(
                    "BearerStrategy.verify",
                    "multiple audiences are not allowed",
                );
            }

            if !&self.options.audience.is_empty()
                && !util::contains_all(&self.options.audience, &token_audience)
            {
                return util::fail_with_log::<Payload>(
                    "BearerStrategy.verify",
                    "audience is not valid",
                );
            }

            // validate scopes
            let token_scopes: Vec<String> = util::extract_claim_vec(&valid.claims, "scp");
            let opt_scopes = &metadata.scopes_supported;

            if !opt_scopes.is_empty() && util::contains_all(opt_scopes, &token_scopes) {
                return util::fail_with_log::<Payload>(
                    "BearerStrategy.verify",
                    "token scopes are not valid",
                );
            }

            Ok(payload)
        } else {
            util::fail_with_log::<Payload>("BearerStrategy.verify", "no JWKS are present")
        }
    }

    pub async fn authenticate(&self, token: String) -> Result<Payload, PassportError> {
        let identity_metadata = &self.options.identity_metadata;
        let metadata_url = util::concat_url(
            identity_metadata.to_string(),
            vec![
                format!(
                    "{}={}",
                    constants::LIBRARY_PRODUCT_PARAMETER_NAME,
                    constants::LIBRARY_PRODUCT
                ),
                format!(
                    "{}={}",
                    constants::LIBRARY_VERSION_PARAMETER_NAME,
                    constants::LIBRARY_VERSION
                ),
            ],
        );
        let mut handler = MetadataHandler::new(metadata_url, String::from("oidc"), None);

        self.jwt_verify(token, &mut handler).await
    }
}

impl Strategy for BearerStrategy {
    fn name(&self) -> String {
        self.name.to_string()
    }

    fn options(&self) -> &StrategyOptions {
        &self.options
    }
}
