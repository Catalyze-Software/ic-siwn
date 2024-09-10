use candid::Principal;
use ic_cdk::query;
use ic_siwn::near::NearAccountId;

use crate::state::{ADDRESS_PRINCIPAL, PRINCIPAL_ADDRESS};

/// Retrieves the principal associated with the given Near account ID address.
///
/// # Arguments
/// * `address` - The Near account ID.
///
/// # Returns
/// * `Ok(Principal)` - The principal if found.
/// * `Err(String)` - An error message if the address cannot be converted or no principal is found.
#[query]
fn get_principal(account_id: String) -> Result<Principal, String> {
    // Create an NearAccountId from the string. This validates the account ID.
    let account_id = NearAccountId::new(&account_id)?;

    ADDRESS_PRINCIPAL.with(|ap| {
        ap.borrow().get(&account_id.to_string()).map_or(
            Err("No principal found for the given address".to_string()),
            |p| Ok(p),
        )
    })
}

/// Retrieves the Near account ID associated with a given IC principal.
///
/// # Arguments
/// * `principal` - A `Principal` containing the principal string.
///
/// # Returns
/// * `Ok(String)` - The Near account ID if found.
/// * `Err(String)` - An error message if the principal cannot be converted or no account ID is found.
#[query]
fn get_account_id(principal: Principal) -> Result<String, String> {
    PRINCIPAL_ADDRESS.with(|pa| {
        pa.borrow().get(&principal).map_or(
            Err("No account ID found for the given principal".to_string()),
            |a| Ok(a),
        )
    })
}

/// Retrieves the Near account ID associated with the caller.
/// This is a convenience function that calls `get_account_id` with the caller's principal.
/// See `get_account_id` for more information.
///
/// # Returns
/// * `Ok(String)` - The Near account ID if found.
/// * `Err(String)` - An error message if the principal cannot be converted or no account ID is found.
#[query]
fn get_caller_address() -> Result<String, String> {
    get_account_id(ic_cdk::caller())
}
