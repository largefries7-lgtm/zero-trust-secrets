//! Session/app state. The unlocked `Vault` (hence the DEK) lives in EXACTLY one
//! place: `AppState::Unlocked(Session)`, owned on the UI thread. `lock()` drops
//! the `Session`, and `Vault`'s `Drop`/`lock` zeroizes the DEK. Never cloned,
//! never serialized, never sent across a thread boundary.

use vaultcore::vault::Vault;

pub struct Session {
    vault: Vault,
}

impl Session {
    pub fn new(vault: Vault) -> Self {
        Session { vault }
    }
    pub fn vault(&self) -> &Vault {
        &self.vault
    }
    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }
}

pub enum AppState {
    Locked,
    Unlocked(Session),
}

impl AppState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, AppState::Unlocked(_))
    }
    /// Transition to Locked, dropping the Session (DEK zeroized on drop).
    pub fn lock(&mut self) {
        *self = AppState::Locked;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultcore::crypto::Argon2Params;
    use vaultcore::secret::{SecretBytes, SecretString};
    use vaultcore::vault::VaultHeader;

    fn unlocked_vault() -> Vault {
        let header = VaultHeader::new_v2(
            false,
            Argon2Params { mem_kib: 8, time: 1, parallelism: 1, salt: [9u8; 16] },
            None,
            vec![1, 2, 3],
            None,
        );
        Vault::new_unlocked(SecretBytes::from_exact(&[5u8; 32]), header)
    }

    #[test]
    fn unlock_then_lock_transitions_and_drops_vault() {
        let mut state = AppState::Unlocked(Session::new(unlocked_vault()));
        assert!(state.is_unlocked());
        state.lock();
        assert!(!state.is_unlocked());
    }

    #[test]
    fn session_exposes_vault_operations() {
        let mut session = Session::new(unlocked_vault());
        session
            .vault_mut()
            .add("email", SecretString::from_string("hunter2".into()))
            .unwrap();
        assert_eq!(session.vault().get("email").unwrap().expose_str(), "hunter2");
    }
}
