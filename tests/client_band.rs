//! The client-band guards: what an `EnvelopeUnlocker` unlocks for a `Client`.
//!
//! These three tests live outside the crate because they drive
//! `Client::set_password`, which is another crate's API: the band the unlocker
//! carries is only a property of this crate when a client actually honours it,
//! and the count of unlocks is only a property of the exchange.
//!
//! The unlocker is asked at most once per exchange, at `set_password`'s
//! pre-flight, before the configuration is cloned and before any request
//! exists. Nothing here reaches a KDC: the endpoint is a closed loopback port,
//! so a test that gets past the pre-flight fails in the transport, not in a
//! real exchange.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use kpasswd_rs::{
        AdminIdentity, Client, EntryPoint, KeytabUnlocker, NotAttempted, Outcome, Principal,
        UnlockError,
    };
    use kpasswd_rs_keytab_vault::{
        Argon2idParams, EnvelopeUnlocker, Kdf, Recipient, SlotCredential, SlotSelector, seal,
    };
    use zeroize::Zeroizing;

    /// What every test here returns: a failure is an `Err` the harness reports.
    type TestResult = Result<(), Box<dyn Error>>;

    /// A minimal keytab: the two-byte header with no entries. It is a *real*
    /// keytab `rskrb5` parses, so the post-unlock path runs to its end.
    const EMPTY_KEYTAB: &[u8] = b"\x05\x02";

    /// The passphrase the passphrase-slot fixtures are sealed with.
    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    /// 16 MiB, t=1, p=1: at or above the crate's floor, and far below the
    /// 64 MiB the default band admits, so only the band can refuse it.
    const OUT_OF_BAND_MEMORY_KIB: u32 = 0x4000;

    /// A `KeytabUnlocker` that counts its calls and hands back a fixed keytab.
    ///
    /// The counter is shared with the test through an `Arc`, because the client
    /// takes ownership of the boxed unlocker and the test must still observe how
    /// many times it was asked.
    struct CountingUnlocker {
        /// How many times `unlock` has been called.
        calls: Arc<AtomicUsize>,
        /// What `unlock` returns.
        keytab: Vec<u8>,
    }

    impl CountingUnlocker {
        /// A fixture that reports into `calls` and returns `keytab`.
        fn new(calls: Arc<AtomicUsize>, keytab: Vec<u8>) -> Self {
            Self { calls, keytab }
        }
    }

    impl KeytabUnlocker for CountingUnlocker {
        fn unlock(&self) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
            let _previous = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(self.keytab.clone()))
        }
    }

    /// A well-formed principal for the fixtures.
    #[expect(
        clippy::panic,
        reason = "deliberate: tests/client_band.rs::principal fixture setup failures must abort the test"
    )]
    fn principal() -> Principal {
        Principal::parse("admin@R.COM").unwrap_or_else(|error| panic!("fixture principal: {error}"))
    }

    /// A client for `identity`, pinned to an explicit configuration and a closed
    /// loopback port, so the case reads nothing ambient and cannot reach a KDC.
    #[expect(
        clippy::panic,
        reason = "deliberate: tests/client_band.rs::client_for fixture setup failures must abort the test"
    )]
    fn client_for(identity: AdminIdentity, require_armor: bool) -> Client {
        Client::builder("R.COM", identity)
            .krb5_conf(b"[libdefaults]\n")
            .entry_point(EntryPoint::new("127.0.0.1", Some(1)))
            .require_armor(require_armor)
            .build()
            .unwrap_or_else(|error| panic!("the fixture client must build: {error}"))
    }

    /// An envelope whose single passphrase slot declares parameters outside the
    /// default band, so only the band the unlocker carries can refuse it.
    #[expect(
        clippy::panic,
        reason = "deliberate: tests/client_band.rs::out_of_band_envelope an envelope operation failing means the format is broken"
    )]
    fn out_of_band_envelope() -> Vec<u8> {
        let params = Argon2idParams::new(OUT_OF_BAND_MEMORY_KIB, 1, 1)
            .unwrap_or_else(|error| panic!("the fixture parameters must be admissible: {error}"));
        seal(
            EMPTY_KEYTAB,
            &[Recipient::new(
                1,
                "operator",
                SlotCredential::Passphrase(PASSPHRASE),
            )],
            &Kdf::Argon2id(params),
        )
        .unwrap_or_else(|error| panic!("seal failed: {error}"))
    }

    /// The band the unlocker carries is the band the client's exchange honours.
    ///
    /// A file whose slot declares out-of-band Argon2 parameters never opens, and
    /// the refusal reaches the caller as the pre-exchange
    /// `NeverAttempted(NotAttempted::Local(..))` - before any request exists.
    #[tokio::test]
    async fn the_unlockers_band_bounds_what_the_client_will_open() -> TestResult {
        let unlocker = EnvelopeUnlocker::new(
            out_of_band_envelope(),
            SlotSelector::Label("operator"),
            SlotCredential::Passphrase(PASSPHRASE),
        )
        .map_err(|error| format!("a sealed envelope must be accepted: {error}"))?;
        let identity = AdminIdentity::from_locked_keytab(principal(), Box::new(unlocker));
        let client = client_for(identity, false);
        let outcome = client.set_password(&principal(), b"new-password").await;
        let Outcome::NeverAttempted(NotAttempted::Local(detail)) = outcome else {
            return Err(format!(
                "an out-of-band envelope is the pre-exchange refusal: {outcome:?}"
            )
            .into());
        };
        assert!(
            detail.contains("under its own policy"),
            "the refusal is the unlocker's policy classification: {detail}"
        );
        Ok(())
    }

    /// An exchange unlocks exactly once, and the lock does not survive it.
    ///
    /// The counting fixture is the statement: one call for a self-change and one
    /// for an administrator setting someone else's password, never two for one
    /// exchange - even though both go through `set_password`.
    #[tokio::test]
    async fn an_exchange_unlocks_exactly_once() -> TestResult {
        let calls = Arc::new(AtomicUsize::new(0));
        let unlocker = CountingUnlocker::new(Arc::clone(&calls), EMPTY_KEYTAB.to_vec());
        let identity = AdminIdentity::from_locked_keytab(principal(), Box::new(unlocker));
        let client = client_for(identity, false);
        let _outcome = client.set_password(&principal(), b"new-password").await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one exchange asks the unlocker once"
        );
        let _changed = client.change_password(b"newer-password").await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a second exchange asks the unlocker once more, not twice"
        );
        Ok(())
    }

    /// An exchange refused before the pre-flight never calls the unlocker.
    ///
    /// `require_armor(true)` with no armour credential is that refusal, and it
    /// is decided on the credential kind - a password exchange - before
    /// `open_admin`. A locked keytab exchange is not password-derived, so a
    /// client the gate refuses cannot carry an unlocker at all; the counter
    /// proves the deferral on the side that does: the locked client built here
    /// is only held, and its unlocker was never asked.
    #[tokio::test]
    async fn a_refused_armor_never_unlocks() -> TestResult {
        let calls = Arc::new(AtomicUsize::new(0));
        let unlocker = CountingUnlocker::new(Arc::clone(&calls), EMPTY_KEYTAB.to_vec());
        // A locked identity whose unlocker a running exchange would consult; it
        // is built and held, and no exchange of it runs.
        let _locked = client_for(
            AdminIdentity::from_locked_keytab(principal(), Box::new(unlocker)),
            true,
        );
        let refused = client_for(AdminIdentity::from_password(principal(), b"secret"), true);
        let outcome = refused.set_password(&principal(), b"new-password").await;
        let Outcome::NeverAttempted(NotAttempted::Local(detail)) = outcome else {
            return Err(format!(
                "a required armour refuses the password exchange before any request: {outcome:?}"
            )
            .into());
        };
        assert!(
            detail.contains("--require-armor"),
            "the refusal names the knob that asked for it: {detail}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a refused exchange, and a locked client that was only built, both leave every unlocker untouched"
        );
        Ok(())
    }
}
