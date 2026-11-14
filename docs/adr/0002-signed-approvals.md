# ADR 0002: Signed approvals

- Status: Accepted
- Date: 2026-11-12
- Deciders: owner (decided 2026-11-12, see Decision)
- Plan: `docs/plans/active/audit-hardening.md` item 3
- Audit: `docs/audit/2026-11-09/01-audit.md`, repros 01 (forged approved claim) and 02 (scripted approve)

## Problem

An approved claim is trusted when `verified.digest` equals a sha256 of the
rendered file (`claims.rs` `claim_verification_digest` / `verify_claim_digest`).
The digest has no key. Anyone who can write a file can compute it, so a
hand-written `status: approved` claim with a recomputed digest passes `reindex`
and `ask` (repro 01). `claim approve` now needs a TTY ceremony, but
`scripts/owner-approve.py` drives it over a pty, so the TTY gate stops pipes and
is not owner proof (CHANGELOG, `approval.rs`). Approval needs something the
writer of a file does not have: a signature by a key the owner controls.

## Threat model

| # | Actor / event | In scope |
|---|---|---|
| T1 | Agent with a shell and a pty, same uid as the owner | yes, but see "Limit of this decision" |
| T2 | Forged claim file, no key access (repro 01) | yes: must fail verification |
| T3 | Key rotation, key loss, key compromise | yes |
| T4 | CI and `make smoke` need scripted approval | yes, without weakening production |
| T5 | macOS and Linux (CI: ubuntu + macos) | yes |

Out of scope: root or kernel compromise, a malicious zbrain binary, physical
access.

## Decision

Owner decision, 2026-11-12:

1. **Key location: a key file outside `ZBRAIN_HOME` (formerly Option B), and it
   is the only backend.** Ed25519 over the existing digest. There is no keyring
   dependency and no signer-backend interface to maintain.
   - Private key: `$XDG_CONFIG_HOME/zbrain-keys/approval.ed25519`; public key
     `approval.pub` and key state `approval.keys.yaml` (active, retired,
     revoked) beside it. `XDG_CONFIG_HOME` falls back to `~/.config` when unset;
     the same path is used on macOS and Linux.
   - Modes: directory `0700`, every file `0600`.
   - Refuse, fail closed, when the key directory or file is a symlink, resolves
     inside `ZBRAIN_HOME`, or has looser modes than above.
   - The public key and key state live in the key directory, so the anchor has
     the private key's protection. `config.yml` gains no trust data, at most
     `signing: required` (a pin, not an anchor).
   - Dependencies: `ed25519-dalek` and `sha2`, plus `base64` (the on-disk
     encoding) and `rand_core` (key generation). No platform code.
2. **Migration: re-sign through one batch owner ceremony.** It lists id, title,
   `verified.at` and digest for every approved claim and lets the owner exclude
   any. Legacy claims stay unsigned and untrusted until re-signed; `doctor`
   prints the exact command. No in-file legacy marker, and no grandfather
   baseline. See "Migration of already-approved claims".
3. **Revoke and supersede signing is a follow-up item, not part of this
   change.** Until it lands, those transitions stay forgeable (repro 04). The
   `alg` / `key_id` / `sig` fields below are reusable for them.

### Limit of this decision

An agent running as the owner's uid can read the owner's files, including the
key file, with `cat` and no prompt. This decision is not owner proof against T1.
It closes T2 only: a forged file now needs the private key, not just a hash.

What it still improves, even against T1:

1. T2 is closed.
2. The attack is no longer "write a file". It becomes "read the key file or
   replace the trust anchor", which is a distinct, auditable action.
3. Stronger steps stay possible later without another format change: a
   passphrase-encrypted key or a hardware key behind the same signature field.

The anchor problem is handled by placement: the public key must not sit under
`ZBRAIN_HOME`, or an agent could replace it and re-sign everything with its own
key. A same-uid agent can still `chmod` and replace the key directory; that is
the same T1 limit.

### How smoke and CI approve without weakening production

- `make smoke` and tests run with a temp `ZBRAIN_HOME` and a temp
  `XDG_CONFIG_HOME`, so the key directory resolves under the temp root. They
  generate a throwaway key there and approve with it. Their anchor is the
  throwaway public key, so a smoke-signed claim is invalid under the owner's
  real home and vice versa.
- Production never honors a key override that points inside the real
  `ZBRAIN_HOME`, and never falls back to an unsigned approval when the signer is
  missing: it fails closed.
- `scripts/owner-approve.py` keeps driving the pty ceremony; the ceremony then
  signs with the test key. The ceremony and the signature are separate gates:
  the TTY confirms presence, the key proves authorship.
- `XDG_CONFIG_HOME` is the only key-path input: there is no `ZBRAIN_KEY_DIR`
  override and no flag. An agent can set it, but it only selects a different
  trust root, not the owner's.

## Considered

### Option A: key in the OS keychain (not chosen)

macOS Keychain, Linux Secret Service (libsecret / gnome-keyring / KWallet), item
`zbrain` / `approval-key-<key_id>` holding the private key and a second item for
the public key and metadata.

Why not chosen:

- Its only edge over the key file is against T1, and only on macOS, through
  per-binary access prompts. That behavior was never tested here (Sources S3).
- On Linux, Secret Service has no per-application gate once the collection is
  unlocked (S4, unverified), so it is no stronger than the key file there.
- It costs the `keyring` crate plus platform backends, D-Bus on Linux, no
  Secret Service on default Linux CI runners, and possible re-prompts when the
  macOS binary identity changes on rebuild.
- The owner chose one simple backend over a second whose value is unproven.

If a prompt-per-use or hardware-backed key is wanted later, it can sit behind
the same `sig` field without a format change.

### Comparison (as evaluated)

| Criterion | A: keychain (not chosen) | B: key file outside ZBRAIN_HOME (chosen) |
|---|---|---|
| T1 same-uid agent reads key | macOS: prompt for a non-trusted binary (untested); Linux: no gate once unlocked | always, silently |
| T2 forged claim (repro 01) | fails | fails |
| Forged claim plus replaced anchor | macOS: modifying another app's item prompts (untested); Linux: allowed | allowed (same uid can chmod and replace) |
| Rotation | new item, old public key kept as retired | same |
| Loss | keychain reset or reinstall loses it; no export by default | file backup is the owner's job |
| CI and `make smoke` | Linux CI has no Secret Service by default; needs a test backend | works anywhere with a temp dir |
| macOS rebuilds | binary identity changes; ad-hoc builds may re-prompt (untested) | none |
| Dependencies | `keyring` plus platform backends, D-Bus on Linux | `ed25519-dalek` plus `sha2` |
| Value against T1 | real on macOS, equal to B on Linux | minimal: stops T2 and accidental writes only |

## On-disk format changes (described, not made)

Claim `verified` block gains fields. Existing fields stay.

```yaml
verified:
  at: 2026-11-12T10:00:00Z
  by: owner
  digest: sha256:...          # unchanged: claim_verification_digest
  alg: ed25519                # new
  key_id: a1b2c3d4e5f60718    # new: first 16 hex of sha256(public key)
  sig: base64...              # new
```

- Signed message: `"zbrain.approval/v1\n" + claim_id + "\n" + verified.digest
  + "\n" + verified.at + "\n" + verified.by + "\n" + key_id`. The digest blanks
  `at`/`by` (`claim_verification_digest`), so signing only the digest would leave
  them forgeable; the signature must bind them.
- Verification: recompute the digest, check `key_id` is in the anchor and not
  revoked-before-`at`, check the signature. Runs on every read path (item 4
  builds the shared path in `claims.rs`): `reindex`, `ask`, `ask --as-of`,
  viewer, MCP resources, `status`.
- `render_claim_markdown` (claims.rs ~811-820) emits the three new keys; parse
  (claims.rs ~474, ~500) accepts them. A claim with `verified.digest` but no
  `sig` is `unsigned` and untrusted after the migration cutover.
- Anchor: `approval.pub` plus `approval.keys.yaml` in the key directory, mode
  `0600`.
- Revoke and supersede are not signed in this change (Decision 3).

## Migration of already-approved claims

Decided: re-sign through one batch owner ceremony (the batch action digest
exists in `approval.rs`).

- The ceremony prints id, title, `verified.at` and digest for each approved
  claim, and lets the owner exclude any. It signs the current canonical content
  of the rest.
- Excluded and not-yet-re-signed legacy claims stay unsigned: not trusted.
  `doctor` lists them with the exact command.
- Residual risk: trust on first use. A claim forged before migration gets signed
  if the owner does not review the list.
- Rejected alternatives: an in-file marker (`verified.legacy: true`) is worthless
  because a forger writes it (repro 01 again); failing closed with no re-sign
  path breaks every existing workspace.

## Key rotation and loss

- Rotation: `key rotate` creates a new key, signs a key-state record with the
  old key, and marks the old key retired at a date. Claims signed by a retired
  key still verify if `verified.at` is before retirement. New approvals use the
  new key. Optional batch re-sign.
- Compromise: mark the key revoked; every claim signed by it becomes unsigned
  until re-signed under a new key after owner review.
- Loss: the public key (and key-state) remain, so existing claims still verify.
  New approvals need a new key, introduced by a recovery ceremony with no old
  key to sign it. That is trust on first use again and must be loud, logged, and
  require typing the new key id.

## Open questions

- Should the key be passphrase-protected, accepting a prompt on every approval?
  Not decided here; the signature field allows it later.
- Ordering with item 4: verification lands first and is a no-op for `sig` until
  this ADR's implementation ships.

## Sources

External claims; this session did not open the doc pages, so S3 and S4 are
unverified recollection of the platform documentation.

- S1: crates.io API, fetched 2026-11-12: `keyring` 4.2.0 (updated 2026-08-29,
  ~39.3M downloads, repo open-source-cooperative/keyring-rs); `ed25519-dalek`
  3.0.0 (updated 2026-07-06, ~272M downloads, dalek-cryptography);
  `security-framework` 3.7.0 (updated 2026-02-20, ~447M downloads);
  `secret-service` 5.2.0 (updated 2026-11-06, ~27.6M downloads); `zeroize` 1.9.1
  (updated 2026-10-06). Version numbers and dates are from the API; API shapes
  and backend feature flags of these versions were not read.
- S2: repository evidence: `crates/zbrain/src/claims.rs` (verification digest,
  render/parse of `verified`), `crates/zbrain/src/approval.rs` (challenge,
  batch action digest, TTY ceremony), `scripts/owner-approve.py` (pty driver),
  `CHANGELOG.md` (TTY is friction), `docs/audit/2026-11-09/repro/01_forge_approved.sh`,
  `02_scripted_approve.sh`.
- S3 (unverified): Apple, "Keychain Services" and "Access Control Lists for
  keychain items" (developer.apple.com/documentation/security/keychain_services):
  an item has a trusted-application list; other applications cause an
  authorization prompt. Behavior for the `security` CLI and for ad-hoc signed
  binaries is untested.
- S4 (unverified): freedesktop.org Secret Service API specification
  (specifications.freedesktop.org/secret-service/latest): clients reach
  collections over the session bus; unlocking is per collection, and the spec
  defines no per-application ACL.
