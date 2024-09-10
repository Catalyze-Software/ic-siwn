use candid::Principal;
use catalyze_shared::{
    state::{init_btree, init_memory_manager},
    MemoryManagerStorage, StorageRef,
};
use ic_cdk::api::set_certified_data;
use ic_certified_map::{fork_hash, labeled_hash, AsHashTree, Hash, RbTree};
use ic_stable_structures::{memory_manager::MemoryId, storable::Blob};
use std::cell::RefCell;

use crate::signature_map::SignatureMap;

pub static PRINCIPAL_ADDRESS_MEMORY_ID: MemoryId = MemoryId::new(0);
pub static ADDRESS_PRINCIPAL_MEMORY_ID: MemoryId = MemoryId::new(1);

pub const LABEL_ASSETS: &[u8] = b"http_assets";
pub const LABEL_SIG: &[u8] = b"sig";

pub(crate) type AssetHashes = RbTree<&'static str, Hash>;

pub(crate) struct State {
    pub signature_map: RefCell<SignatureMap>,
    pub asset_hashes: RefCell<AssetHashes>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            signature_map: RefCell::new(SignatureMap::default()),
            asset_hashes: RefCell::new(AssetHashes::default()),
        }
    }
}

thread_local! {
    static STATE: State = State::default();
    static MEMORY_MANAGER: MemoryManagerStorage = init_memory_manager();
    static PRINCIPAL_ADDRESS: StorageRef<Principal, String> = init_btree(&MEMORY_MANAGER, PRINCIPAL_ADDRESS_MEMORY_ID);
    static ADDRESS_PRINCIPAL: StorageRef<[u8;20], String> = init_btree(&MEMORY_MANAGER, ADDRESS_PRINCIPAL_MEMORY_ID);
}

pub(crate) fn update_root_hash(asset_hashes: &AssetHashes, signature_map: &SignatureMap) {
    let prefixed_root_hash = fork_hash(
        &labeled_hash(LABEL_ASSETS, &asset_hashes.root_hash()),
        &labeled_hash(LABEL_SIG, &signature_map.root_hash()),
    );
    set_certified_data(&prefixed_root_hash[..]);
}
