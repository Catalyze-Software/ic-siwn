use std::fmt::{self, Display};

use base64::{engine::general_purpose, Engine};

pub const NEAR_SIGNATURE_LENGTH: usize = 64;

#[derive(Debug)]
pub enum NearError {
    AccountIdValidationError(near_account_id::ParseAccountError),
    DecodingError(base64::DecodeError),
    InvalidSignature,
    // PublicKeyRecoveryFailure, // TODO: add
}

impl fmt::Display for NearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NearError::AccountIdValidationError(e) => {
                write!(f, "Account ID validation error: {}", e)
            }
            NearError::DecodingError(e) => write!(f, "Decoding error: {}", e),
            NearError::InvalidSignature => write!(f, "Invalid signature"),
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
        NearError::DecodingError(err)
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
        near_account_id::AccountId::validate(address)?;
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
    /// Creates a new `EthSignature` after validating the Near signature format.
    ///
    /// The signature must be encoded as base-64 string.
    ///
    /// # Arguments
    /// * `signature` - A string slice representing the Near signature.
    pub fn new(signature: &str) -> Result<NearSignature, NearError> {
        let mut buffer = Vec::<u8>::new();

        general_purpose::STANDARD.decode_vec(signature, &mut buffer)?;

        if buffer.len() != NEAR_SIGNATURE_LENGTH {
            return Err(NearError::InvalidSignature);
        }

        Ok(NearSignature(signature.to_owned()))
    }

    /// Returns a string slice of the Near signature.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the Near signature into a byte vector.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::new();

        general_purpose::STANDARD
            .decode_vec(self.0.clone(), &mut buffer)
            .unwrap();

        buffer
    }

    /// Converts the Near signature into a byte array.
    pub fn as_byte_array(&self) -> [u8; 64] {
        let bytes = self.as_bytes();
        let mut array = [0; NEAR_SIGNATURE_LENGTH];
        array.copy_from_slice(&bytes);
        array
    }
}
