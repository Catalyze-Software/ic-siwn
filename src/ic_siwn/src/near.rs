use std::fmt::{self, Display};

use borsh::BorshSerialize;
use ed25519_dalek::{Verifier, VerifyingKey};

use crate::{coding, hash::hash_bytes, SiwnMessage};

pub const NEAR_SIGNATURE_LENGTH: usize = 64;

#[derive(Debug)]
pub enum NearError {
    AccountIdValidationError(near_account_id::ParseAccountError),
    DecodingError(String),
    PayloadSerializationError(std::io::Error),
    InvalidSignature(String),
    PublicKeyParseError(ed25519_dalek::ed25519::Error),
}

impl fmt::Display for NearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NearError::AccountIdValidationError(e) => {
                write!(f, "Account ID validation error: {}", e)
            }
            NearError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            NearError::PayloadSerializationError(e) => {
                write!(f, "Payload serialization error: {}", e)
            }
            NearError::PublicKeyParseError(e) => write!(f, "Public key parse error: {}", e),
            NearError::InvalidSignature(e) => write!(f, "Invalid signature: {}", e),
        }
    }
}

impl From<near_account_id::ParseAccountError> for NearError {
    fn from(err: near_account_id::ParseAccountError) -> Self {
        NearError::AccountIdValidationError(err)
    }
}

impl From<base64::DecodeError> for NearError {
    fn from(err: base64::DecodeError) -> Self {
        NearError::DecodingError(err.to_string())
    }
}

impl From<base64::DecodeSliceError> for NearError {
    fn from(err: base64::DecodeSliceError) -> Self {
        NearError::DecodingError(err.to_string())
    }
}

impl From<bs58::decode::Error> for NearError {
    fn from(err: bs58::decode::Error) -> Self {
        NearError::DecodingError(err.to_string())
    }
}

impl From<std::io::Error> for NearError {
    fn from(err: std::io::Error) -> Self {
        NearError::PayloadSerializationError(err)
    }
}

impl From<ed25519_dalek::ed25519::Error> for NearError {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        NearError::PublicKeyParseError(err)
    }
}

impl From<NearError> for String {
    fn from(error: NearError) -> Self {
        error.to_string()
    }
}

/// Represents an Near account ID with validation.
///
/// This struct ensures that the contained Near account ID string is valid according to Near standards.

#[derive(Debug)]
pub struct NearAccountId(String);

impl NearAccountId {
    /// Creates a new `NearAccountId` after validating the Near account ID format and encoding.
    /// # Arguments
    /// * `address` - A string slice representing the Near address.
    pub fn new(address: &str) -> Result<Self, NearError> {
        near_account_id::AccountId::validate(address)
            .map_err(NearError::AccountIdValidationError)?;
        Ok(Self(address.to_owned()))
    }

    /// Returns a string slice of the Near account ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the Near account ID into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let account_id: near_account_id::AccountId = self.0.parse().unwrap();
        account_id.as_bytes().to_vec()
    }
}

impl Display for NearAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents an Near signature with validation.
///
/// This struct ensures that the contained Near signature string is valid.
/// It checks for correct length and hex encoding.
#[derive(Debug)]
pub struct NearSignature(String);

impl NearSignature {
    /// Creates a new `NearSignature` after validating the Near signature format.
    ///
    /// The signature must be encoded as base-64 string.
    ///
    /// # Arguments
    /// * `signature` - A string slice representing the Near signature.
    pub fn new(signature: &str) -> Result<NearSignature, NearError> {
        let buffer = crate::coding::base64_decode_vec(signature)?;

        if buffer.len() != NEAR_SIGNATURE_LENGTH {
            return Err(NearError::InvalidSignature(format!(
                "Invalid signature length: {}",
                buffer.len()
            )));
        }

        Ok(NearSignature(signature.to_owned()))
    }

    /// Returns a string slice of the Near signature.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the Near signature into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        crate::coding::base64_decode_vec(self.0.clone().as_str()).unwrap()
    }

    /// Converts the Near signature into a byte array.
    pub fn as_byte_array(&self) -> [u8; 64] {
        let bytes = self.as_bytes();
        let mut array = [0; NEAR_SIGNATURE_LENGTH];
        array.copy_from_slice(&bytes);
        array
    }
}

impl Display for NearSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(BorshSerialize)]
pub struct Payload {
    pub message: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
}

// https://github.com/near/NEPs/blob/master/neps/nep-0413.md
pub struct SignMessageOptionsNEP0413 {
    pub tag: u32,
    pub payload: Payload,
}

impl SignMessageOptionsNEP0413 {
    pub fn new(payload: Payload) -> Self {
        SignMessageOptionsNEP0413 {
            // https://github.com/near/NEPs/blob/master/neps/nep-0413.md#signature
            // 4-bytes borsh representation of 2^31+413, as the prefix tag.
            tag: 2147484061,
            payload,
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], NearError> {
        let tag = borsh::to_vec(&self.tag)?;
        let payload = borsh::to_vec(&self.payload)?;
        let payload = [tag.clone(), payload].concat();

        Ok(hash_bytes(payload))
    }
}

impl TryFrom<SiwnMessage> for SignMessageOptionsNEP0413 {
    type Error = NearError;

    fn try_from(message: SiwnMessage) -> Result<Self, Self::Error> {
        let nonce = crate::coding::base64_decode_slice_32(&message.nonce)?;

        let payload = Payload {
            message: message.to_string(),
            nonce,
            recipient: message.account_id,
            callback_url: Some(message.callback_url),
        };

        Ok(SignMessageOptionsNEP0413::new(payload))
    }
}

pub fn verify_near_public_key(
    signature: String,
    message: SiwnMessage,
    public_key: String,
) -> Result<(), NearError> {
    let payload: SignMessageOptionsNEP0413 = message.try_into()?;
    let payload = payload.hash()?;

    // Near public key is encoded base58 string
    let public_key = coding::bs58_decode_slice_32(&public_key)?;
    let public_key = VerifyingKey::from_bytes(&public_key)?;

    let signature = NearSignature::new(&signature)?;
    let signature = signature.as_byte_array();
    let signature = ed25519_dalek::Signature::from_bytes(&signature);

    public_key
        .verify(&payload, &signature)
        .map_err(|e| NearError::InvalidSignature(e.to_string()))
}
