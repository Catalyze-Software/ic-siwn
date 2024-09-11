use std::fmt;

use candid::{CandidType, Principal};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use simple_asn1::ASN1EncodeErr;

use crate::{
    delegation::{
        create_delegation, create_delegation_hash, create_user_canister_pubkey, generate_seed,
        DelegationError,
    },
    hash,
    nonce::generate_nonce,
    settings::Settings,
    siwn::{SiwnMessage, SiwnMessageError},
    verify_near_public_key, with_settings, NearAccountId, NearError, NearSignature, SignatureMap,
    SIWN_MESSAGES,
};

const MAX_SIGS_TO_PRUNE: usize = 10;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PrepareLoginDetails {
    pub message: String,
    pub nonce: String,
    pub callback_url: String,
}

/// This function is the first step of the user login process. It validates the provided Near account ID,
/// creates a SIWN message, saves it for future use, and returns it.
///
/// # Parameters
/// * `account_id`: A [`crate::near::NearAccountId`] representing the user's Near account ID. This account ID
///   is validated and used to create the SIWN message.
///
/// # Returns
/// A `Result` that, on success, contains a [`crate::siwn::SiwnMessage`] with the `nonce` inside of it.
/// The `nonce` is used in the login function to prevent replay and ddos attacks.
///
pub fn prepare_login(account_id: &NearAccountId) -> Result<PrepareLoginDetails, NearError> {
    let nonce = generate_nonce();
    let message = SiwnMessage::new(account_id, &nonce);

    // Save the SIWN message for use in the login call
    SIWN_MESSAGES.with_borrow_mut(|msgs| {
        msgs.insert(message.clone(), account_id, &nonce);
    });

    Ok(PrepareLoginDetails {
        message: message.to_string(),
        nonce,
        callback_url: message.callback_url,
    })
}
/// Login details are returned after a successful login. They contain the expiration time of the
/// delegation and the user canister public key.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LoginDetails {
    /// The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
    /// the delegation will no longer be valid.
    pub expiration: u64,

    /// The user canister public key. This key is used to derive the user principal.
    pub user_canister_pubkey: ByteBuf,
}

pub enum LoginError {
    NearError(NearError),
    SiwnMessageError(SiwnMessageError),
    AccountIdMismatch,
    DelegationError(DelegationError),
    ASN1EncodeErr(ASN1EncodeErr),
}

impl From<NearError> for LoginError {
    fn from(err: NearError) -> Self {
        LoginError::NearError(err)
    }
}

impl From<SiwnMessageError> for LoginError {
    fn from(err: SiwnMessageError) -> Self {
        LoginError::SiwnMessageError(err)
    }
}

impl From<DelegationError> for LoginError {
    fn from(err: DelegationError) -> Self {
        LoginError::DelegationError(err)
    }
}

impl From<ASN1EncodeErr> for LoginError {
    fn from(err: ASN1EncodeErr) -> Self {
        LoginError::ASN1EncodeErr(err)
    }
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::NearError(e) => write!(f, "{}", e),
            LoginError::SiwnMessageError(e) => write!(f, "{}", e),
            LoginError::AccountIdMismatch => write!(f, "Recovered account ID does not match"),
            LoginError::DelegationError(e) => write!(f, "{}", e),
            LoginError::ASN1EncodeErr(e) => write!(f, "{}", e),
        }
    }
}

/// Handles the second step of the user login process. It verifies the signature against the SIWN message,
/// creates a delegation for the session, adds it to the signature map, and returns login details
///
/// # Parameters
/// * `signature`: The SIWN message signature to verify.
/// * `account_id`: The Near account ID used to sign the SIWN message.
/// * `session_key`: A unique session key to be used for the delegation.
/// * `signature_map`: A mutable reference to `SignatureMap` to which the delegation hash will be added
///   after successful validation.
/// * `canister_id`: The principal of the canister performing the login.
/// * `nonce`: The nonce generated during the `prepare_login` call.
///
/// # Returns
/// A `Result` that, on success, contains the [LoginDetails] with session expiration and user canister
/// public key, or an error string on failure.
pub fn login(
    signature: &NearSignature,
    account_id: &NearAccountId,
    public_key: String,
    session_key: ByteBuf,
    signature_map: &mut SignatureMap,
    canister_id: &Principal,
    nonce: &str,
) -> Result<LoginDetails, LoginError> {
    // Remove expired SIWN messages from the state before proceeding. The init settings determines
    // the time to live for SIWN messages.
    SIWN_MESSAGES.with_borrow_mut(|msgs| {
        // Prune any expired SIWN messages from the state.
        msgs.prune_expired();

        // Get the previously created SIWN message for current account ID. If it has expired or does not
        // exist, return an error.
        let message = msgs.get(account_id, nonce)?;

        // Verify the supplied signature against the SIWN message and recover the Near account ID
        // used to sign the message.
        let result = verify_near_public_key(signature.to_string(), message.clone(), public_key)
            .map_err(LoginError::NearError);

        // Ensure the SIWN message is removed from the state both on success and on failure.
        msgs.remove(account_id, nonce);

        // Handle the result of the signature verification.
        result?;

        // The delegation is valid for the duration of the session as defined in the settings.
        let expiration = with_settings!(|settings: &Settings| {
            message
                .issued_at
                .saturating_add(settings.session_expires_in)
        });

        // The seed is what uniquely identifies the delegation. It is derived from the salt, the
        // Ethereum address and the SIWN message URI.
        let seed = generate_seed(account_id);

        // Before adding the signature to the signature map, prune any expired signatures.
        signature_map.prune_expired(ic_cdk::api::time(), MAX_SIGS_TO_PRUNE);

        // Create the delegation and add its hash to the signature map. The seed is used as the map key.
        let delegation = create_delegation(session_key, expiration)?;
        let delegation_hash = create_delegation_hash(&delegation);
        signature_map.put(hash::hash_bytes(seed), delegation_hash);

        // Create the user canister public key from the seed. From this key, the client can derive the
        // user principal.
        let user_canister_pubkey = create_user_canister_pubkey(canister_id, seed.to_vec())?;

        Ok(LoginDetails {
            expiration,
            user_canister_pubkey: ByteBuf::from(user_canister_pubkey),
        })
    })
}
