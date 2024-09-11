use candid::Principal;
use url::Url;

const DEFAULT_SIGN_IN_EXPIRES_IN: u64 = 60 * 5 * 1_000_000_000; // 5 minutes
const DEFAULT_SESSION_EXPIRES_IN: u64 = 30 * 60 * 1_000_000_000; // 30 minutes
const DEFAULT_CHAIN_ID: &str = "mainnet";

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeFeature {
    // Enabling this feature will include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,
}

/// Represents the settings for initializing SIWN.
///
/// This struct is used to configure SIWN functionality.
/// It includes settings such as domain, scheme, statement, and expiration times for sessions and sign-ins.
///
/// Use the [`SettingsBuilder`] to create a new instance of `Settings` to validate inputs and use default values.
///
/// The SIWN library needs to be initialized with a `Settings` instance before it can be used. Call the [`crate::init()`] function
/// to initialize the library.
#[derive(Default, Debug, Clone)]
pub struct Settings {
    /// The full app URL, from where the frontend that uses SIWN is served.
    /// Example: "https://example.com".
    /// Will be used as a "Recipient" message signing parameter - The recipient of the message.
    pub app_url: String,

    /// The URL that the wallet will call with the signature.
    pub callback_url: String,

    pub chain_id: String,

    /// The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
    pub salt: String, // TODO: Do we need it?

    /// The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: u64,

    /// The TTL for a session in nanoseconds.
    pub session_expires_in: u64,

    /// The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    /// that the delegation is allowed for all canisters.
    pub targets: Option<Vec<Principal>>,

    // Optional runtime features that can be enabled for SIWN.
    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

pub struct SettingsBuilder {
    settings: Settings,
}

impl SettingsBuilder {
    /// Creates a new `SettingsBuilder` with the specified domain, URI, and salt.
    /// This is the starting point for building a `Settings` struct.
    ///
    /// # Parameters
    ///
    /// * `app_url`: The full app URL from where the frontend that uses SIWN is served.
    /// * `callback_url`: The URL that the wallet will call with the signature.
    /// * `salt`: The salt is used when generating the seed that uniquely identifies each user principal.
    pub fn new<S: Into<String>, T: Into<String>, U: Into<String>>(
        app_url: S,
        callback_url: T,
        salt: U,
    ) -> Self {
        SettingsBuilder {
            settings: Settings {
                app_url: app_url.into(),
                callback_url: callback_url.into(),
                salt: salt.into(),
                chain_id: DEFAULT_CHAIN_ID.to_owned(),
                sign_in_expires_in: DEFAULT_SIGN_IN_EXPIRES_IN,
                session_expires_in: DEFAULT_SESSION_EXPIRES_IN,
                targets: None,
                runtime_features: None,
            },
        }
    }

    pub fn chain_id(mut self, chain_id: String) -> Self {
        self.settings.chain_id = chain_id;
        self
    }

    /// Sign in messages are valid for a limited time, after which they expire. The `sign_in_expires_in` value is
    /// the time-to-live (TTL) for a sign-in message in nanoseconds. Defaults to 5 minutes.
    pub fn sign_in_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.sign_in_expires_in = expires_in;
        self
    }

    /// Sessions (as represented by delegete identities) are valid for a limited time, after which they expire.
    /// The `session_expires_in` value is the time-to-live (TTL) for a session in nanoseconds. Defaults to 30 minutes.
    pub fn session_expires_in(mut self, expires_in: u64) -> Self {
        self.settings.session_expires_in = expires_in;
        self
    }

    /// The `targets` is a list of `Principal`s representing the canisters where the delegated identity can be used to
    /// authenticate the user. Defaults to None, which means that the delegation is allowed for any canister.
    pub fn targets(mut self, targets: Vec<Principal>) -> Self {
        self.settings.targets = Some(targets);
        self
    }

    /// Optional runtime features customize the behavior of ic-siwN.
    pub fn runtime_features(mut self, features: Vec<RuntimeFeature>) -> Self {
        self.settings.runtime_features = Some(features);
        self
    }

    pub fn build(self) -> Result<Settings, String> {
        validate_uri(&self.settings.app_url)?;
        validate_uri(&self.settings.callback_url)?;
        validate_chain_id(&self.settings.chain_id)?;
        validate_salt(&self.settings.salt)?;
        validate_sign_in_expires_in(self.settings.sign_in_expires_in)?;
        validate_session_expires_in(self.settings.session_expires_in)?;
        validate_targets(&self.settings.targets)?;

        Ok(self.settings)
    }
}

fn validate_uri(uri: &str) -> Result<String, String> {
    let parsed_uri = Url::parse(uri).map_err(|_| String::from("Invalid URI"))?;
    if !parsed_uri.has_host() {
        Err(String::from("Invalid URI"))
    } else {
        Ok(uri.to_string())
    }
}

fn validate_salt(salt: &str) -> Result<String, String> {
    if salt.is_empty() {
        return Err(String::from("Salt cannot be empty"));
    }
    // Salt can only contain printable ASCII characters
    if salt.chars().any(|c| !c.is_ascii() || !c.is_ascii_graphic()) {
        return Err(String::from("Invalid salt"));
    }
    Ok(salt.to_string())
}

fn validate_sign_in_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Sign in expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_session_expires_in(expires_in: u64) -> Result<u64, String> {
    if expires_in == 0 {
        return Err(String::from("Session expires in must be greater than 0"));
    }
    Ok(expires_in)
}

fn validate_chain_id(chain_id: &str) -> Result<String, String> {
    if chain_id.is_empty() {
        return Err(String::from("Chain ID cannot be empty"));
    }
    if chain_id != "mainnet" || chain_id != "testnet" {
        return Err(String::from("Invalid chain ID"));
    }
    Ok(chain_id.to_string())
}

fn validate_targets(targets: &Option<Vec<Principal>>) -> Result<Option<Vec<Principal>>, String> {
    if let Some(targets) = targets {
        if targets.is_empty() {
            return Err(String::from("Targets cannot be empty"));
        }

        // There is a limit of 1000 targets
        if targets.len() > 1000 {
            return Err(String::from("Too many targets"));
        }

        // Duplicate targets are not allowed
        let mut targets_clone = targets.clone();
        targets_clone.sort();
        targets_clone.dedup();
        if targets_clone.len() != targets.len() {
            return Err(String::from("Duplicate targets are not allowed"));
        }
    }
    Ok(targets.clone())
}
