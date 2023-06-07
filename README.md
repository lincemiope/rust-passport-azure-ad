# rust-passport-azure-ad

Port of passport-azure-ad to Rust

## Installation

```bash
cargo add passport_azure_ad
```

## Usage

```rust
use passport_azure_ad::{
    bearer_strategy::BearerStrategy,
    error::PassportError,
    types::{LogLevel, Payload},
    util,
};
use std::env;
use dotenvy::dotenv;

#[tokio::test]
async fn test_msal_bearer() {
    dotenv().ok();
    let token = env::var("BEARER_TOKEN")
        .expect("'BEARER_TOKEN' is not defined")
        .to_string();
    let client_id = env::var("AZURE_AD_CLIENT_ID")
        .expect("'AZURE_AD_CLIENT_ID' is not defined")
        .to_string();
    let tenant_id = env::var("AZURE_AD_TENANT_ID")
        .expect("'AZURE_AD_TENANT_ID' is not defined")
        .to_string();

    let bearer = BearerStrategy::build(
        Some(false),                                       // allow_multi_audiences
        None,                                              // audience
        Some(client_id),                                   // client_id
        None,                                              // clock_skew
        Some(util::open_id_config_url(tenant_id.clone())), // identity_metadata
        Some(false),                                       // ignore_expiration
        Some(false),                                       // is_b2c
        Some(vec![util::issuer_url(tenant_id)]),           // issuer
        Some(LogLevel::Trace),                             // log_level
        None,                                              // policy_name
        Some(vec![String::from("api-access")]),            // scope
        Some(true),                                        // validate_issuer
    )
    .unwrap();

    let validated: Result<Payload, PassportError> = bearer.authenticate(token).await;

    assert!(validated.is_ok());
}
```

## License

[MIT](https://choosealicense.com/licenses/mit/)