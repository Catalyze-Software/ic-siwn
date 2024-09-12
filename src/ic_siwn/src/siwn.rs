use crate::near::NearAccountId;
use crate::settings::Settings;
use crate::{hash, with_settings};
use candid::{CandidType, Deserialize};
use catalyze_shared::impl_storable_for;
use ic_cdk::api::time;
use ic_certified_map::Hash;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

impl_storable_for!(SiwnMessage);

#[derive(Debug)]
pub enum SiwnMessageError {
    MessageNotFound,
}

impl fmt::Display for SiwnMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SiwnMessageError::MessageNotFound => write!(f, "Message not found"),
        }
    }
}

impl From<SiwnMessageError> for String {
    fn from(error: SiwnMessageError) -> Self {
        error.to_string()
    }
}

/// Represents a SIWN (Sign-In With Near) message.
///
#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct SiwnMessage {
    pub app_url: String,
    pub callback_url: String,
    pub account_id: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expiration_time: u64,
}

impl SiwnMessage {
    /// Constructs a new `SiwnMessage` for a given Near account_id using the settings defined in the
    /// global [`Settings`] struct.
    ///
    /// # Arguments
    ///
    /// * `account_id`: The Near account_id of the user.
    /// * `nonce`: The nonce generated during the [`crate::login::prepare_login`] call.
    pub fn new(account_id: &NearAccountId, nonce: &str) -> Self {
        let current_time = time();

        with_settings!(|settings: &Settings| {
            SiwnMessage {
                callback_url: settings.callback_url.clone(),
                chain_id: settings.chain_id.clone(),
                app_url: settings.app_url.clone(),
                account_id: account_id.as_str().to_string(),
                nonce: nonce.to_string(),
                issued_at: time(),
                expiration_time: current_time + settings.sign_in_expires_in,
            }
        })
    }

    /// Checks if the SIWN message is currently valid.
    ///
    /// # Returns
    ///
    /// `true` if the message is within its valid time period, `false` otherwise.
    pub fn is_expired(&self) -> bool {
        let current_time = time();
        self.issued_at < current_time || current_time > self.expiration_time
    }
}

impl fmt::Display for SiwnMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let issued_at_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.issued_at as i128).unwrap();
        let issued_at_iso_8601 = issued_at_datetime.format(&Rfc3339).unwrap();

        let expiration_datetime =
            OffsetDateTime::from_unix_timestamp_nanos(self.expiration_time as i128).unwrap();
        let expiration_iso_8601 = expiration_datetime.format(&Rfc3339).unwrap();

        let msg = format!(
            "{app_url} wants you to sign in with your Near account:\n\
            {account_id}\n\n\
            URI: {app_url}\n\
            Callback URL: {nonce}\n\
            Chain ID: {chain_id}\n\
            Nonce: {nonce}\n\
            Issued At: {issued_at_iso_8601}\n\
            Expiration Time: {expiration_iso_8601}",
            app_url = self.app_url,
            chain_id = self.chain_id,
            account_id = self.account_id,
            nonce = self.nonce,
        );
        write!(f, "{}", msg)
    }
}

/// The SiwnMessageMap map key is the hash of the caller account_id and the message nonce.
/// This ensures every call to `siwe_prepare_login` leads to one new copy of the SIWN message being stored.
pub fn siwn_message_map_hash(account_id: &NearAccountId, nonce: &str) -> Hash {
    let mut bytes: Vec<u8> = vec![];

    let account_id_bytes = account_id.as_bytes();
    bytes.push(account_id_bytes.len() as u8);
    bytes.extend(account_id_bytes);

    let nonce_bytes = nonce.as_bytes();
    bytes.push(nonce_bytes.len() as u8);
    bytes.extend(nonce_bytes);

    hash::hash_bytes(bytes)
}

/// The SiwnMessageMap is a map of SIWN messages keyed by the Ethereum account_id of the user. SIWN messages
/// are stored in the map during the course of the login process and are removed once the login process
/// is complete. The map is also pruned periodically to remove expired SIWN messages.
pub struct SiwnMessageMap {
    map: HashMap<[u8; 32], SiwnMessage>,
}

impl SiwnMessageMap {
    pub fn new() -> SiwnMessageMap {
        SiwnMessageMap {
            map: HashMap::new(),
        }
    }

    /// Removes SIWN messages that have exceeded their time to live.
    pub fn prune_expired(&mut self) {
        let current_time = time();
        self.map
            .retain(|_, message| message.expiration_time > current_time);
    }

    /// Adds a SIWN message to the map.
    pub fn insert(&mut self, message: SiwnMessage, account_id: &NearAccountId, nonce: &str) {
        let hash = siwn_message_map_hash(account_id, nonce);
        self.map.insert(hash, message);
    }

    /// Returns a cloned SIWN message associated with the provided account_id or an error if the message
    /// does not exist.
    pub fn get(
        &self,
        account_id: &NearAccountId,
        nonce: &str,
    ) -> Result<SiwnMessage, SiwnMessageError> {
        let hash = siwn_message_map_hash(account_id, nonce);
        self.map
            .get(&hash)
            .cloned()
            .ok_or(SiwnMessageError::MessageNotFound)
    }

    /// Removes the SIWN message associated with the provided account_id.
    pub fn remove(&mut self, account_id: &NearAccountId, nonce: &str) {
        let hash = siwn_message_map_hash(account_id, nonce);
        self.map.remove(&hash);
    }
}

impl Default for SiwnMessageMap {
    fn default() -> Self {
        Self::new()
    }
}
