use super::constants;
use super::error::PassportError;
use serde_json::Value;

/// Concatenates a url with a vector of parameter=value(s)
///
/// Example:
/// concat_url(
///     String::from("https://www.duckduckgo.com/"),
///     vec![
///         "hps=1",
///         "q=something",
///         "ia=definition"
///     ].iter().map(|e| e.to_string()).collect());
pub fn concat_url(url: String, rest: Vec<String>) -> String {
    let mut first_mark = '?';

    if url.contains('?') {
        first_mark = '&';
    }

    [url, first_mark.to_string(), rest.join("&")].join("")
}

/// Checks if a vector of T contais all Ts in content
pub fn contains_all<T: std::cmp::PartialEq>(container: &[T], content: &[T]) -> bool {
    content.iter().all(|c| container.contains(c))
}

/// Checks if a vector v1 and a vector v2 contain the same elements
pub fn vec_diff<T: std::cmp::PartialEq>(v1: &Vec<T>, v2: &Vec<T>) -> bool {
    v1.len() != v2.len() || !contains_all(v1, v2) || !contains_all(v2, v1)
}

fn extract_claim_value(claims: &Value, claim: &str) -> Value {
    claims.as_object().unwrap().get(claim).unwrap().clone()
}

/// Estracts a claim from a decoded JWT token payload as a vector of String
pub fn extract_claim_vec(claims: &Value, claim: &str) -> Vec<String> {
    let value = extract_claim_value(claims, claim);

    if value.is_array() {
        return value
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.to_string())
            .collect();
    }

    value
        .as_str()
        .unwrap()
        .split(',')
        .map(|e| e.to_string())
        .collect()
}

/// Estracts a claim from a decoded JWT token payload as a String
pub fn extract_claim_string(claims: &Value, claim: &str) -> String {
    extract_claim_value(claims, claim).to_string()
}

/// Returns open id configuration url for tenant_id
pub fn open_id_config_url(tenant_id: String) -> String {
    format!(
        "{}{}/v2.0/.well-known/openid-configuration",
        constants::AAD,
        tenant_id
    )
}

/// Returns issuer url for tenant_id
pub fn issuer_url(tenant_id: String) -> String {
    format!("{}{}/v2.0", constants::AAD, tenant_id)
}

/// Prints a message before returning it as an error
pub fn fail_with_log<T>(source: &str, message: &str) -> Result<T, PassportError> {
    let error = PassportError::from((source.to_string(), message.to_string()));
    println!("[ERROR] {}", error);
    Err(error)
}
