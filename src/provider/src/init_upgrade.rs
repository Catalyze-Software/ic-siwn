use candid::{CandidType, Principal};
use ic_cdk::{init, post_upgrade};
use ic_siwn::settings::SettingsBuilder;
use serde::Deserialize;

#[derive(CandidType, Debug, Clone, PartialEq, Deserialize)]
pub enum RuntimeFeature {
    // Include the app frontend URI as part of the identity seed.
    IncludeUriInSeed,
}

/// Represents the settings that determine the behavior of the SIWN library. It includes settings such as domain, scheme, statement,
/// and expiration times for sessions and sign-ins.
#[derive(CandidType, Deserialize, Debug, Clone)]
pub struct SettingsInput {
    /// The full app URL, from where the frontend that uses SIWN is served.
    /// Example: "https://example.com".
    /// Will be used as a "Recipient" message signing parameter - The recipient of the message.
    pub app_url: String,

    /// The message that the user is signing. Could be static because the nonce is included in the signing parameters.
    pub message: Option<String>,

    /// The URL that the wallet will call with the signature.
    pub callback_url: String,

    /// The salt is used when generating the seed that uniquely identifies each user principal. The salt can only contain
    /// printable ASCII characters.
    pub salt: String,

    /// The TTL for a sign-in message in nanoseconds. After this time, the sign-in message will be pruned.
    pub sign_in_expires_in: Option<u64>,

    /// The TTL for a session in nanoseconds.
    pub session_expires_in: Option<u64>,

    /// The list of canisters for which the identity delegation is allowed. Defaults to None, which means
    /// that the delegation is allowed for all canisters. If specified, the canister id of this canister must be in the list.
    pub targets: Option<Vec<String>>,

    pub runtime_features: Option<Vec<RuntimeFeature>>,
}

/// Initialize the SIWN library with the given settings.
///
/// Required fields are `app_url`, `callback_url`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `callback_url` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
fn siwn_init(settings_input: SettingsInput) {
    let mut ic_siwn_settings = SettingsBuilder::new(
        &settings_input.app_url,
        &settings_input.callback_url,
        &settings_input.salt,
    );

    // Optional fields
    if let Some(message) = settings_input.message {
        ic_siwn_settings = ic_siwn_settings.message(message);
    }
    if let Some(expire_in) = settings_input.sign_in_expires_in {
        ic_siwn_settings = ic_siwn_settings.sign_in_expires_in(expire_in);
    }
    if let Some(session_expire_in) = settings_input.session_expires_in {
        ic_siwn_settings = ic_siwn_settings.session_expires_in(session_expire_in);
    }
    if let Some(targets) = settings_input.targets {
        let targets: Vec<Principal> = targets
            .into_iter()
            .map(|t| Principal::from_text(t).unwrap())
            .collect();
        // Make sure the canister id of this canister is in the list of targets
        let canister_id = ic_cdk::id();
        if !targets.contains(&canister_id) {
            panic!(
                "ic_siwn_provider canister id {} not in the list of targets",
                canister_id
            );
        }
        ic_siwn_settings = ic_siwn_settings.targets(targets);
    }

    if let Some(runtime_features) = settings_input.runtime_features {
        for feature in runtime_features {
            match feature {
                RuntimeFeature::IncludeUriInSeed => {
                    ic_siwn_settings = ic_siwn_settings.runtime_features(vec![
                        ic_siwn::settings::RuntimeFeature::IncludeUriInSeed,
                    ]);
                }
            }
        }
    }

    // Build and initialize SIWN
    ic_siwn::init::init(ic_siwn_settings.build().unwrap()).unwrap();
}

/// `init` is called when the canister is created. It initializes the SIWN library with the given settings.
///
/// Required fields are `app_url`, `callback_url`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `callback_url` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[init]
fn init(settings: SettingsInput) {
    siwn_init(settings);
}

/// `post_upgrade` is called when the canister is upgraded. It initializes the SIWN library with the given settings.
///
/// Required fields are `app_url`, `callback_url`, and `salt`. All other fields are optional.
///
/// ## 🛑 Important: Changing the `salt` or `callback_url` setting affects how user seeds are generated.
/// This means that existing users will get a new principal id when they sign in. Tip: Don't change the `salt` or `uri`
/// settings after users have started using the service!
#[post_upgrade]
fn upgrade(settings: SettingsInput) {
    siwn_init(settings);
}
