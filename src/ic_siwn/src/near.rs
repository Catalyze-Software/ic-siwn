use std::fmt::{self, Display};

use borsh::BorshSerialize;

use crate::SiwnMessage;

pub const NEAR_SIGNATURE_LENGTH: usize = 64;

#[derive(Debug)]
pub enum NearError {
    AccountIdValidationError(near_account_id::ParseAccountError),
    DecodingError(String),
    PayloadSerializationError(std::io::Error),
    InvalidSignature(String),
    PublicKeyParseError(String),
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

impl From<std::io::Error> for NearError {
    fn from(err: std::io::Error) -> Self {
        NearError::PayloadSerializationError(err)
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
        near_sdk::AccountId::validate(address).map_err(NearError::AccountIdValidationError)?;
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
        let buffer = crate::base64::decode_vec(signature)?;

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
        crate::base64::decode_vec(self.0.clone().as_str()).unwrap()
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

// https://github.com/near/NEPs/blob/master/neps/nep-0413.md
#[derive(BorshSerialize)]
pub struct SignMessageOptionsNEP0413 {
    pub tag: u64,
    pub message: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
}

impl TryFrom<SiwnMessage> for SignMessageOptionsNEP0413 {
    type Error = NearError;

    fn try_from(message: SiwnMessage) -> Result<Self, Self::Error> {
        let nonce = crate::base64::decode_slice_32(&message.nonce)?;

        let result = SignMessageOptionsNEP0413 {
            // https://github.com/near/NEPs/blob/master/neps/nep-0413.md#signature
            // 4-bytes borsh representation of 2^31+413, as the prefix tag.
            tag: 2147484061,
            message: message.to_string(),
            recipient: message.app_url,
            nonce,
            callback_url: Some(message.callback_url),
        };

        Ok(result)
    }
}

pub fn verify_near_public_key(
    signature: String,
    message: SiwnMessage,
    public_key: String,
) -> Result<(), NearError> {
    let payload: SignMessageOptionsNEP0413 = message.try_into()?;
    let payload = borsh::to_vec(&payload)?;

    let public_key = format!("ed25519:{public_key}")
        .as_str()
        .parse::<near_sdk::PublicKey>()
        .map_err(|err| NearError::PublicKeyParseError(err.to_string()))?;

    let public_key = public_key.as_bytes();
    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);

    let signature = NearSignature::new(&signature)?;
    let signature = signature.as_byte_array();

    public_key
        .verify(&payload, &signature)
        .map_err(|e| NearError::InvalidSignature(e.to_string()))
}
