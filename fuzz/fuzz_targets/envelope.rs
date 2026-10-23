//! The vault's envelope parser on arbitrary bytes: `parse` must refuse every
//! malformed file by name, `slots` must read what the header claims, and the
//! selection's `check_cost_band` must settle a hostile Argon2 header without
//! deriving anything. The CI job runs this with `-timeout=60`, so an input that
//! buys more than a minute of work is a libFuzzer finding rather than a run the
//! wall clock quietly cuts short. (The credential kind is not consulted by
//! selection; the unlock paths are left to the unit tests' fake KDF backend.)

#![no_main]

use kpasswd_rs_keytab_vault::{KdfLimits, KeytabEnvelope, SlotCredential, SlotSelector};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = KeytabEnvelope::parse(data) {
        #[expect(
            clippy::let_underscore_must_use,
            clippy::let_underscore_untyped,
            let_underscore_drop,
            reason = "deliberate: fuzz/fuzz_targets/envelope.rs::fuzz_target the harness drives the call for panics and hangs; its value is not the property"
        )]
        let _ = envelope.slots();
        if let Ok(selection) = envelope.select_slot(
            SlotSelector::Index(0),
            &KdfLimits::defaults(),
            &SlotCredential::Passphrase(b"fuzz"),
        ) {
            #[expect(
                clippy::let_underscore_must_use,
                clippy::let_underscore_untyped,
                reason = "deliberate: fuzz/fuzz_targets/envelope.rs::fuzz_target the harness drives the cost check for panics and hangs; its verdict is not the property"
            )]
            let _ = selection.check_cost_band();
        }
    }
});
