/// AAD
pub const AAD: &str = "https://login.microsoftonline.com/";

/// POLICY_REGEX
/// Must be case insensitive
pub const POLICY_REGEX: &str = r"^b2c_1a?_[0-9a-z._-]+$";

/// CLOCK_SKEW
/// 5 minutes
pub const CLOCK_SKEW: u32 = 300;

/// LIBRARY_PRODUCT
pub const LIBRARY_PRODUCT: &str = "passport-azure-ad";

/// LIBRARY_VERSION_PARAMETER_NAME
pub const LIBRARY_VERSION_PARAMETER_NAME: &str = "x-client-Ver";

/// LIBRARY_PRODUCT_PARAMETER_NAME
pub const LIBRARY_PRODUCT_PARAMETER_NAME: &str = "x-client-SKU";

/// LIBRARY_VERSION
pub const LIBRARY_VERSION: &str = "4.0.0";

/// CACHE_TTL
pub const CACHE_TTL: u64 = 1800;
