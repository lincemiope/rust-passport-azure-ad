use dotenvy::dotenv;
use passport_azure_ad::{
    bearer_strategy::BearerStrategy,
    types::{LogLevel, Payload, StrategyOptionsParams},
    util,
};
use std::{env, error::Error};

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

    let bearer = BearerStrategy::build(StrategyOptionsParams {
        clock_stew: None,
        validate_issuer: Some(true),
        allow_multi_audiences: Some(false),
        audience: None,
        is_b2c: Some(false),
        policy_name: None,
        issuer: Some(vec![util::issuer_url(tenant_id.clone())]),
        client_id: Some(client_id),
        identity_metadata: Some(util::open_id_config_url(tenant_id)),
        scope: Some(vec![String::from("api-access")]),
        log_level: Some(LogLevel::Trace),
        ignore_expiration: Some(false),
    })
    .unwrap();

    let validated: Result<Payload, Box<dyn Error>> = bearer.authenticate(token).await;

    assert!(validated.is_ok());
}
