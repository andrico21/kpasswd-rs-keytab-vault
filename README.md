# kpasswd-rs-keytab-vault

This crate keeps a Kerberos keytab encrypted while it is stored. That is all it does. It protects copies of the file, not the machine or the process that uses the keytab.

It defines an encrypted file format for keytabs and an unlocker for [`kpasswd-rs`](https://crates.io/crates/kpasswd-rs), which on its own reads only plain keytabs. The file stays encrypted on disk, and the keytab is decrypted in memory only when `kpasswd-rs` is about to use it.

## Why

A keytab is a password that nobody has to type. Anyone with a copy can authenticate as its principal from any machine that can reach the KDC, and the copy keeps working until the principal's key is changed in the KDC. For service and admin principals, that rarely happens.

The usual way to store a keytab is a plain file with mode `0600` on a volume, or a Kubernetes Secret mounted into the pod. File permissions protect the live file and nothing else. Full copies of it end up in volume snapshots and backups, in volumes that a `Retain` policy keeps after the app is gone, on disks that get attached to another node, and, for a Secret, in etcd and every backup of it. Base64 is not encryption, and Secrets sit in etcd in the clear unless the cluster encrypts them at rest. Whoever runs the storage, the CSI driver or the backups can read those copies, and so can anyone allowed to read Secrets in the namespace.

Copying a file usually leaves no trace, and a copied keytab works exactly like the original: if the principal can reset passwords, so can whoever holds the copy. If another team runs the platform, you can't even check where the copies go.

With this crate, those copies are useless on their own, as long as the key is kept somewhere else. To get the keytab back, you need the encrypted file and, separately, the key that opens it.

## How it works

The keytab is encrypted once, with XChaCha20-Poly1305 under a random 256-bit data key. That data key is then wrapped into up to eight slots, and any one of them opens the file. A slot is opened either by a raw 32-byte key, used as is, or by a passphrase, which is stretched with Argon2id (by default 64 MiB, 3 passes, 4 lanes). Raw keys are meant for machines, and `openssl rand -hex 32` makes a good one. Passphrases are meant for people and for break-glass access. The whole file is authenticated, so a file that was modified or truncated won't open.

The part that matters most is where you keep the key. It has to live somewhere the file doesn't, so that no single snapshot, backup or admin gets both. A common setup is the encrypted keytab on the volume and the key in a Kubernetes Secret or a systemd credential (`LoadCredential=`).

At runtime, `EnvelopeUnlocker` holds the encrypted bytes and decrypts them only when `kpasswd-rs` asks for the keytab. It hands the keytab over in a buffer that is wiped when it is dropped, and keeps no copy of its own. The file format and the crypto details are in the [API docs](https://docs.rs/kpasswd-rs-keytab-vault).

## What it doesn't protect against

It won't save you if the pod or the host is compromised. The process has to read the key to unlock the file, so anyone who can run code in the pod, or is root on the node, can read the key as well, or grab the keytab while it is decrypted. Swap, core dumps and VM memory snapshots can catch it in memory too.

It doesn't help if the key lives next to the file: on the same volume, in the same Secret, in the same backup job, or readable by the same person, such as a namespace admin who can both read the Secret and mount the volume. Then the encryption adds a step, not protection, and the crate has no way to tell where your key is. Check how your backups are taken, too. A file-level backup that reads the pod's mounts collects the key together with the file.

It does nothing about copies that leaked before. Plain keytabs in old backups, on laptops or attached to tickets keep working after you switch, so change the principal's key in the KDC (a new kvno) when you start. That makes those copies worthless.

A passphrase is only as good as the passphrase. Someone with a stolen file can guess offline. Argon2id makes each guess expensive, not impossible, and the file is only as strong as its weakest slot.

Rotating a slot key is not revocation. `rewrap_slot` keeps the same data key, old copies of the file still open with the old key, and anyone who could open the file before may have kept the keytab. Revocation means a new principal key in the KDC, followed by a fresh seal.

Finally, it doesn't limit what the principal can do, it doesn't record who unlocked the file, and it doesn't tie the file to a machine; there is no TPM or HSM involved. Keep the principal's rights as narrow as you can.

## Usage

The keytab belongs to whichever principal makes the password change. That can be an account with reset rights that calls `set_password` for other principals, or any principal that changes its own password with `change_password`; `kpasswd-rs` calls it an `AdminIdentity` either way. A principal that changes its own password gets new keys, so export a fresh keytab and seal it again afterwards.

Seal the keytab once, then hand `kpasswd-rs` a locked keytab:

```rust
use kpasswd_rs::{AdminIdentity, Principal};
use kpasswd_rs_keytab_vault::{
    EnvelopeUnlocker, Kdf, Recipient, SlotCredential, SlotSelector, raw_key_from_bytes, seal,
};

// 32 raw bytes or 64 hex characters, kept away from the keytab.
let key = raw_key_from_bytes(&std::fs::read("/run/secrets/keytab-key")?)?;

// Once: encrypt the keytab, then get rid of the plain copy.
let sealed = seal(
    &std::fs::read("service.keytab")?,
    &[Recipient::new(1, "app", SlotCredential::RawKey(&key))],
    &Kdf::default(),
)?;
std::fs::write("service.keytab.sealed", &sealed)?;

// At runtime: nothing is decrypted until a password change needs the keytab.
let unlocker = EnvelopeUnlocker::new(
    std::fs::read("service.keytab.sealed")?,
    SlotSelector::Label("app"),
    SlotCredential::RawKey(&key),
)?;
let identity = AdminIdentity::from_locked_keytab(
    Principal::parse("svc-app@EXAMPLE.COM")?,
    Box::new(unlocker),
);
```

The format doesn't care whose keytab it holds, so it can also keep one for another program. Call `unlocker.unlock()` yourself (the method comes from the `kpasswd_rs::KeytabUnlocker` trait, so import it): you get the plain keytab in a buffer that is wiped when dropped, and keeping it off disk from there on is up to you.

### Several slots

A file can have up to eight slots, and any one of them opens it. A common pair is a raw key for the service and a passphrase that people keep for break-glass access:

```rust
// `passphrase` holds the break-glass passphrase as bytes.
let sealed = seal(
    &std::fs::read("service.keytab")?,
    &[
        Recipient::new(1, "app", SlotCredential::RawKey(&key)),
        Recipient::new(2, "break-glass", SlotCredential::Passphrase(&passphrase)),
    ],
    &Kdf::default(),
)?;

// The service keeps opening slot "app" with its key. A person opens the same file with the passphrase:
let unlocker = EnvelopeUnlocker::new(
    sealed,
    SlotSelector::Label("break-glass"),
    SlotCredential::Passphrase(&passphrase),
)?;
```

Every slot has an id and a label, both unique in the file. You name the slot to open by its label, or by its position with `SlotSelector::Index`, counting from zero. The slots are fixed when the file is sealed: `rewrap_slot` replaces the key of an existing slot, but adding or removing a slot means sealing the keytab again.

### Passphrase cost

The only thing you can tune is how expensive a passphrase is to guess. The cipher, the key sizes and the file layout are fixed on purpose, so every reader and writer agrees on them, and raw-key slots have no cost to tune at all.

By default a passphrase slot uses Argon2id with RFC 9106's second recommended setting: 64 MiB, 3 passes, 4 lanes. Sealing or unlocking a passphrase slot needs that memory for a moment, wherever it runs. If only people use the passphrase, as in the break-glass setup above, you can raise the cost without the service ever paying it. The setting is stored in the file and applies to every passphrase slot sealed in the same call:

```rust
use kpasswd_rs_keytab_vault::{Argon2idParams, KdfLimits};

// 256 MiB (the first number is in KiB), 3 passes, 4 lanes.
let params = Argon2idParams::new(256 * 1024, 3, 4)?;
// Same keytab and recipients as above, with the higher cost.
let sealed = seal(&keytab, &recipients, &Kdf::Argon2id(params))?;
```

An unlock only accepts the settings it is told to accept, so a tampered file can't make it use more memory than you allowed. By default it accepts the default setting alone, so whatever opens a passphrase slot sealed with your own setting has to name it:

```rust
let unlocker = EnvelopeUnlocker::new(
    sealed,
    SlotSelector::Label("break-glass"),
    SlotCredential::Passphrase(&passphrase),
)?
.kdf_limits(KdfLimits::between(params, params)?);
```

`KdfLimits::between` takes a range, so one reader can accept several settings, and `rewrap_slot_with_limits` takes the same range when you rotate such a slot. `Argon2idParams::new` accepts anything from 8 MiB, 1 pass, 1 lane upward. RFC 9106's first recommended setting is 2 GiB, 1 pass, 4 lanes, if the machines that unlock can spare the memory.

## Compatibility and license

The crate needs Rust 1.99 or newer. It is pre-1.0, so a minor release may break the API. It is licensed under MIT or Apache-2.0, at your option.
