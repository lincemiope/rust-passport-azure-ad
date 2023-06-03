/// POLICY_REGEX
/// Must be case insensitive
pub static POLICY_REGEX: &str = r"^b2c_1a?_[0-9a-z._-]+$/";

/// CLOCK_STEW
/// 5 minutes
pub static CLOCK_STEW: u32 = 300;

/// CLIENT_ASSERTION_JWT_LIFETIME
/// 10 minutes
pub static CLIENT_ASSERTION_JWT_LIFETIME: u32 = 600;

/// CLIENT_ASSERTION_TYPE
pub static CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// LIBRARY_PRODUCT
pub static LIBRARY_PRODUCT: & str = "passport-azure-ad";

/// LIBRARY_VERSION_PARAMETER_NAME
pub static LIBRARY_VERSION_PARAMETER_NAME: &str = "x-client-Ver";

/// LIBRARY_PRODUCT_PARAMETER_NAME
pub static LIBRARY_PRODUCT_PARAMETER_NAME: &str = "x-client-SKU";

/// LIBRARY_VERSION
pub static LIBRARY_VERSION: &str = "4.0.0";
