use ic_cdk::update;
use ic_siwn::{NearAccountId, PrepareLoginDetails};

/// Prepare the login by generating a challenge (the SIWN message) and returning it to the caller.
///
/// # Arguments
/// * `account_id` (String): The Near account ID of the user to prepare the login for.
///
/// # Returns
/// * `Ok(PrepareLoginDetails)`: The SIWN message with details used in the login function.
/// * `Err(String)`: An error message if the account ID is invalid.
#[update]
fn siwn_prepare_login(account_id: String) -> Result<PrepareLoginDetails, String> {
    // Create an NearAccountId from the string. This validates the account ID.
    let account_id = NearAccountId::new(&account_id)?;

    ic_siwn::prepare_login(&account_id).map_err(|e| e.to_string())
}
