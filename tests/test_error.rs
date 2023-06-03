use passport_azure_ad::error::PassportError;
use passport_azure_ad::util::fail_with_log;

// call with --nocapture to see the message
fn try_smt(value: i32) -> Result<(), PassportError> {
    if value < 0 {
        return fail_with_log("try_smt", "'value' must be positive");
    }

    Ok(())
}

#[test]
#[should_panic]
fn test_error() {
    let d = try_smt(-2);

    assert!(d.is_ok())
}
