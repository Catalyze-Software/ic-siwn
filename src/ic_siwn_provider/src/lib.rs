use ic_cdk::query;

mod general;
mod init_upgrade;
mod siwn_get_delegation;
mod siwn_login;
mod siwn_prepare_login;
mod state;

#[query]
fn icts_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}

#[query]
fn icts_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Hacky way to expose the candid interface to the outside world
#[query(name = "__get_candid_interface_tmp_hack")]
pub fn __export_did_tmp_() -> String {
    use crate::init_upgrade::SettingsInput;
    use candid::{export_service, Principal};
    use ic_siwn::{LoginDetails, PrepareLoginDetails, SignedDelegation};
    use serde_bytes::ByteBuf;

    export_service!();
    __export_service()
}

// Method used to save the candid interface to a file
#[test]
pub fn candid() {
    catalyze_shared::candid::save_candid_file(
        "../../candid/ic_siwn_provider.did",
        __export_did_tmp_(),
    );
}
