use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;

mod coding;
mod delegation;
mod hash;
mod init;
mod login;
mod macros;
mod near;
mod nonce;
mod settings;
mod signature_map;
mod siwn;

pub use delegation::*;
pub use init::*;
pub use login::*;
pub use near::*;
pub use settings::*;
pub use signature_map::*;
pub use siwn::*;

thread_local! {
    // The random number generator is used to generate nonces for SIWN messages.
    static RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };

    // The settings control the behavior of the SIWN library. The settings must be initialized
    // before any other library functions are called.
    static SETTINGS: RefCell<Option<Settings>> = const { RefCell::new(None) };

    // SIWN messages are stored in global state during the login process. The key is the
    // Near address as a byte array and the value is the SIWN message. After a successful
    // login, the SIWN message is removed from state.
    static SIWN_MESSAGES: RefCell<SiwnMessageMap> = RefCell::new(SiwnMessageMap::new());
}
