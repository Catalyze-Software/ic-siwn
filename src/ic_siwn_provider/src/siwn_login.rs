use candid::Principal;
use ic_cdk::update;
use ic_siwn::{LoginDetails, NearAccountId, NearSignature};
use serde_bytes::ByteBuf;

use crate::state::{update_root_hash, ACCOUNT_ID_PRINCIPAL, PRINCIPAL_ACCOUNT_ID, STATE};

/// Authenticates the user by verifying the signature of the SIWN message. This function also
/// prepares the delegation to be fetched in the next step, the `siwn_get_delegation` function.
///
/// # Arguments
/// * `signature` (String): The signature of the SIWN message.
/// * `account_id` (String): The Near account_id of the user.
/// * `public_key` (String): The Near account public key of the user.
/// * `session_key` (ByteBuf): A unique key that identifies the session.
/// * `nonce` (String): The nonce generated during the `prepare_login` call.
///
/// # Returns
/// * `Ok(LoginOkResponse)`: Contains the user canister public key and other login response data if the login is successful.
/// * `Err(String)`: An error message if the login process fails.
#[update]
fn siwn_login(
    signature: String,
    account_id: String,
    public_key: String,
    session_key: ByteBuf,
    nonce: String,
) -> Result<LoginDetails, String> {
    STATE.with(|state| {
        let signature_map = &mut *state.signature_map.borrow_mut();

        // Create an NearAccountId from the string. This validates the account ID.
        let account_id = NearAccountId::new(&account_id)?;

        // Create an EthSignature from the string. This validates the signature.
        let signature = NearSignature::new(&signature)?;

        // Attempt to log in with the provided signature, address, and session key.
        let login_response = ic_siwn::login(
            &signature,
            &account_id,
            public_key,
            session_key,
            &mut *signature_map,
            &ic_cdk::api::id(),
            &nonce,
        )
        .map_err(|e| e.to_string())?;

        // Update the certified data of the canister due to changes in the signature map.
        update_root_hash(&state.asset_hashes.borrow(), signature_map);

        // Convert the user canister public key to a principal.
        let principal = Principal::self_authenticating(&login_response.user_canister_pubkey);

        // Store the mapping of principal to Ethereum address and vice versa if the settings allow it.
        manage_principal_account_id_mappings(&principal, &account_id);

        Ok(login_response)
    })
}

fn manage_principal_account_id_mappings(principal: &Principal, account_id: &NearAccountId) {
    PRINCIPAL_ACCOUNT_ID.with(|pa| {
        pa.borrow_mut().insert(*principal, account_id.to_string());
    });

    ACCOUNT_ID_PRINCIPAL.with(|ap| {
        ap.borrow_mut().insert(account_id.to_string(), *principal);
    });
}
