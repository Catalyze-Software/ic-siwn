use std::{collections::HashMap, fmt};

use super::hash::{self, Value};
use crate::{
    coding,
    near::NearAccountId,
    settings::{RuntimeFeature, Settings},
    signature_map::SignatureMap,
    with_settings,
};

use ic_certified_map::{Hash, HashTree};
use serde_bytes::ByteBuf;

use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use simple_asn1::{from_der, oid, ASN1Block, ASN1EncodeErr};

#[derive(Debug)]
pub enum DelegationError {
    SignatureNotFound,
    WitnessHashMismatch(Hash, Hash),
    SerializationError(String),
    InvalidSessionKey(String),
    InvalidExpiration(String),
    SignatureExpired,
}

impl fmt::Display for DelegationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegationError::SignatureNotFound => write!(f, "Signature not found"),
            DelegationError::WitnessHashMismatch(witness_hash, root_hash) => write!(
                f,
                "Internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
                coding::base64_encode(witness_hash),
                coding::base64_encode(root_hash)
            ),
            DelegationError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            DelegationError::InvalidSessionKey(e) => write!(f, "Invalid session key: {}", e),
            DelegationError::InvalidExpiration(e) => write!(f, "Invalid expiration: {}", e),
            DelegationError::SignatureExpired => write!(f, "Signature expired"),
        }
    }
}

impl From<DelegationError> for String {
    fn from(error: DelegationError) -> Self {
        error.to_string()
    }
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Delegation {
    pub pubkey: ByteBuf,
    pub expiration: u64,
    pub targets: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    pub signature: ByteBuf,
}

#[derive(Serialize)]
struct CertificateSignature<'a> {
    certificate: ByteBuf,
    tree: HashTree<'a>,
}

/// Generates a unique seed for delegation, derived from the salt, Near account ID, and SIWN message URI.
///
/// # Parameters
/// * `account_id`: The Near account ID as a string slice.
///
/// # Returns
/// A `Hash` value representing the unique seed.
pub fn generate_seed(account_id: &NearAccountId) -> Hash {
    with_settings!(|settings: &Settings| {
        let mut seed: Vec<u8> = vec![];

        let salt = settings.salt.as_bytes();
        seed.push(salt.len() as u8);
        seed.extend_from_slice(salt);

        let address_bytes = account_id.as_str().as_bytes();
        seed.push(address_bytes.len() as u8);
        seed.extend(address_bytes);

        // Only include the URI in the seed if the runtime feature is enabled
        match settings.runtime_features {
            Some(ref features) if features.contains(&RuntimeFeature::IncludeUriInSeed) => {
                let uri = settings.app_url.as_bytes();
                seed.push(uri.len() as u8);
                seed.extend_from_slice(uri);
            }
            _ => (),
        }

        hash::hash_bytes(seed)
    })
}

/// Creates a delegation with the provided session key and expiration, including a list of canisters for identity delegation.
///
/// # Parameters
/// * `session_key`: A key uniquely identifying the session.
/// * `expiration`: Expiration time in nanoseconds since the UNIX epoch.
pub fn create_delegation(
    session_key: ByteBuf,
    expiration: u64,
) -> Result<Delegation, DelegationError> {
    // Validate the session key and expiration
    if session_key.is_empty() {
        return Err(DelegationError::InvalidSessionKey(
            "Session key is empty".to_string(),
        ));
    }

    // Validate the session key is DER-encoded
    from_der(&session_key).map_err(|e| {
        DelegationError::InvalidSessionKey(format!("Session key should be DER-encoded: {}", e))
    })?;

    if expiration == 0 {
        return Err(DelegationError::InvalidExpiration(
            "Expiration is 0".to_string(),
        ));
    }
    with_settings!(|settings: &Settings| {
        Ok(Delegation {
            pubkey: session_key.clone(),
            expiration,
            targets: settings.targets.clone(),
        })
    })
}

pub fn create_delegation_hash(delegation: &Delegation) -> Hash {
    let mut delegation_map = HashMap::new();

    delegation_map.insert("pubkey", Value::Bytes(&delegation.pubkey));
    delegation_map.insert("expiration", Value::U64(delegation.expiration));

    if let Some(targets) = delegation.targets.as_ref() {
        let mut arr = Vec::with_capacity(targets.len());
        for t in targets.iter() {
            arr.push(Value::Bytes(t.as_ref()));
        }
        delegation_map.insert("targets", Value::Array(arr));
    }

    let delegation_map_hash = hash::hash_of_map(delegation_map);

    hash::hash_with_domain(b"ic-request-auth-delegation", &delegation_map_hash)
}

/// Constructs a hash tree as proof of an entry in the signature map.
///
/// # Parameters
/// * `signature_map`: The map of signatures.
/// * `seed`: The unique seed identifying the delegation.
/// * `delegation_hash`: The hash of the delegation.
pub fn witness(
    signature_map: &SignatureMap,
    seed: Hash,
    delegation_hash: Hash,
) -> Result<HashTree, DelegationError> {
    let seed_hash = hash::hash_bytes(seed);

    if signature_map.is_expired(ic_cdk::api::time(), seed_hash, delegation_hash) {
        return Err(DelegationError::SignatureExpired);
    }

    let witness = signature_map
        .witness(seed_hash, delegation_hash)
        .ok_or(DelegationError::SignatureNotFound)?;

    let witness_hash = witness.reconstruct();
    let root_hash = signature_map.root_hash();
    if witness_hash != root_hash {
        return Err(DelegationError::WitnessHashMismatch(
            witness_hash,
            root_hash,
        ));
    }

    Ok(witness)
}

/// Creates a DER-encoded public key for a user canister from a given seed.
///
/// # Parameters
/// * `seed`: Bytes representing the seed.
/// * `canister_id`: The principal of the canister for which the public key is created.
///
/// # Returns
/// Bytes of the DER-encoded public key.
pub(crate) fn create_user_canister_pubkey(
    canister_id: &Principal,
    seed: Vec<u8>,
) -> Result<Vec<u8>, ASN1EncodeErr> {
    let canister_id: Vec<u8> = canister_id.as_slice().to_vec();

    let mut key: Vec<u8> = vec![];
    key.push(canister_id.len() as u8);
    key.extend(canister_id);
    key.extend(seed);

    let algorithm = oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2);
    let algorithm = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, algorithm)]);
    let subject_public_key = ASN1Block::BitString(0, key.len() * 8, key.to_vec());
    let subject_public_key_info = ASN1Block::Sequence(0, vec![algorithm, subject_public_key]);
    simple_asn1::to_der(&subject_public_key_info)
}

/// Creates a certified signature using a certificate and a state hash tree.
///
/// # Parameters
/// * `certificate`: Bytes representing the certificate.
/// * `tree`: The `HashTree` used for certification.
///
/// # Returns
/// A `Result` containing the certified signature or an error.
pub fn create_certified_signature(
    certificate: Vec<u8>,
    tree: HashTree,
) -> Result<Vec<u8>, DelegationError> {
    let certificate_signature = CertificateSignature {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    cbor_serialize(&certificate_signature)
}

/// Serializes data into CBOR format.
///
/// # Parameters
/// * `data`: The data to serialize.
///
/// # Returns
/// A `Result` containing CBOR serialized data or an error.
fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, DelegationError> {
    let mut cbor_serializer = serde_cbor::ser::Serializer::new(Vec::new());

    cbor_serializer
        .self_describe()
        .map_err(|e| DelegationError::SerializationError(e.to_string()))?;

    data.serialize(&mut cbor_serializer)
        .map_err(|e| DelegationError::SerializationError(e.to_string()))?;

    Ok(cbor_serializer.into_inner())
}
