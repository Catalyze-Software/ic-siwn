use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;
use settings::Settings;
use siwn::SiwnMessageMap;

pub mod hash;
pub mod init;
pub mod macros;
pub mod near;
pub mod settings;
pub mod siwn;

thread_local! {
    // The random number generator is used to generate nonces for SIWE messages.
    static RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };

    // The settings control the behavior of the SIWE library. The settings must be initialized
    // before any other library functions are called.
    static SETTINGS: RefCell<Option<Settings>> = const { RefCell::new(None) };

    // SIWN messages are stored in global state during the login process. The key is the
    // Near address as a byte array and the value is the SIWN message. After a successful
    // login, the SIWN message is removed from state.
    static SIWE_MESSAGES: RefCell<SiwnMessageMap> = RefCell::new(SiwnMessageMap::new());
}
