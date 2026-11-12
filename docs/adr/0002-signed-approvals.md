# ADR 0002: Signed approvals

- Status: Proposed
- Date: 2026-11-12
- Deciders: owner (decision pending). This ADR states options; it does not decide the key location.
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
| T1 | Agent with a shell and a pty, same uid as the owner | yes, but see "What no option can do" |
| T2 | Forged claim file, no key access (repro 01) | yes: must fail verification |
| T3 | Key rotation, key loss, key compromise | yes |
| T4 | CI and `make smoke` need scripted approval | yes, without weakening production |
| T5 | macOS and Linux (CI: ubuntu + macos) | yes |

Out of scope: root or kernel compromise, a malicious zbrain binary, physical
access.

## What no option can do

An agent running as the owner's uid can read the owner's files, call the owner's
D-Bus session, and run the owner's `zbrain`. Neither option below is owner
proof against T1. Stated plainly:

- A key file (B) is readable by that agent with `cat`, no prompt.
- A keychain item (A) is readable by that agent unless the platform shows a
  prompt or refuses. On macOS an item has an access list of trusted apps; a
  different binary asking for it triggers a user prompt (unverified here, see
  Sources S3). On Linux Secret Service, once the collection is unlocked, any
  client on the session bus can read it; there is no per-application gate in
  the specification (S4, unverified).

What signing does improve, even against T1:

1. T2 is closed. A forged file needs the private key, not just a hash.
2. The attack is no longer "write a file". It becomes "read a secret or replace
   the trust anchor", which is a distinct, auditable action (keychain prompt,
   key-file access, anchor change).
3. It makes stronger steps possible later without another format change:
   a prompt per use (macOS access control), a passphrase-encrypted key, or a
   hardware key (YubiKey / Secure Enclave) behind the same signature field.

The anchor problem applies to both options. Verification needs the public key
from a place the agent cannot rewrite. If the public key sits in `config.yml`
under `ZBRAIN_HOME`, an agent replaces it and re-signs everything with its own
key. So the public key must live with the private key's protection (inside the
keychain item, or in the key directory with the file).

## Options

### Option A: key in the OS keychain

macOS Keychain, Linux Secret Service (libsecret / gnome-keyring / KWallet).
Item `zbrain` / `approval-key-<key_id>` holds the Ed25519 private key; a second
item holds the public key and metadata.

### Option B: key file outside ZBRAIN_HOME

For example `$XDG_CONFIG_HOME/zbrain-keys/approval.ed25519` (macOS and Linux),
mode `0600`, directory `0700`, refused if the path resolves inside
`ZBRAIN_HOME`, is a symlink, or has loose modes. Public key in `approval.pub`
beside it.

### Comparison

| Criterion | A: keychain | B: key file outside ZBRAIN_HOME |
|---|---|---|
| T1 same-uid agent reads key | macOS: prompt for a non-trusted binary (untested); Linux: no gate once unlocked | always, silently |
| T2 forged claim (repro 01) | fails | fails |
| Forged claim plus replaced anchor | macOS: modifying another app's item prompts (untested); Linux: allowed | allowed (same uid can chmod and replace) |
| Rotation | new item, old public key kept as retired; same cost | same |
| Loss | keychain reset or reinstall loses it; no export by default | file backup is the owner's job; easy to back up (also easy to leak) |
| CI and `make smoke` | Linux CI runners have no Secret Service by default; needs a test backend | works anywhere with a temp dir |
| macOS rebuilds | binary identity changes on rebuild; ad-hoc signed dev builds may re-prompt (untested) | none |
| Dependencies | `keyring` plus platform backends, larger tree, D-Bus on Linux | `ed25519-dalek` plus `sha2`; no new platform code |
| Honest value against T1 | real on macOS, equal to B on Linux | minimal: stops T2 and accidental writes only |

### How smoke and CI approve without weakening production

Both options use the same mechanism: a test trust root.

- `make smoke` and tests run with a temp `ZBRAIN_HOME` and a temp
  `ZBRAIN_KEY_DIR`. They generate a throwaway key there and approve with it.
  Their anchor is the throwaway public key, so a smoke-signed claim is invalid
  under the owner's real home and vice versa.
- Production never honors a key override that points inside the real
  `ZBRAIN_HOME`, and never falls back to an unsigned approval when the signer is
  missing: it fails closed.
- `scripts/owner-approve.py` keeps driving the pty ceremony; the ceremony then
  signs with the test key. The ceremony and the signature are separate gates:
  the TTY confirms presence, the key proves authorship.
- The key override env var is a convenience for tests. An agent can set it, but
  it only selects a different trust root, not the owner's.

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
- Option A: anchor in keychain (`approval-pub-<key_id>`), plus a small
  `key_state` item listing active and retired key ids with dates.
- Option B: `approval.pub` plus `approval.keys.yaml` (active, retired, revoked)
  in the key directory, mode `0600`.
- Revoke and supersede (repro 04) are forgeable the same way. Signing
  transitions is a separate decision but reuses `alg/key_id/sig`; listed under
  open questions.
- `config.yml` gains no trust data. At most `signing: required` (a pin, not an
  anchor).

## Migration of already-approved claims

| Choice | Effect | Risk |
|---|---|---|
| Re-sign | Owner runs one batch ceremony (the batch action digest exists in `approval.rs`) that lists every approved claim and signs the current canonical content | trust on first use: a claim forged before migration gets signed if the owner does not review the list |
| Grandfather with in-file marker (`verified.legacy: true`) | No owner action | worthless: a forger writes the marker (repro 01 again) |
| Reject | Fail closed; every approved claim becomes a draft | safest, and breaks every existing workspace |

Recommended: re-sign through one batch ceremony. The ceremony prints id, title,
`verified.at` and digest for each claim, and lets the owner exclude any. Until
re-signed, a legacy claim is treated as unsigned: not trusted, shown by `doctor`
with the exact command. A grandfathered baseline is acceptable only as an
owner-signed manifest of digests created at migration time, never as a marker
inside a claim.

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

## Recommendation (proposal, owner decides)

Adopt Ed25519 over the existing digest and choose Option A (keychain) as the
owner's production key, with Option B kept as the headless and test backend
behind the same signer interface.

Why A: it is the only option that changes anything against T1 at all, via
per-binary access control and prompts on macOS, and it keeps the anchor out of
the writable filesystem. T2 is closed either way.

Strongest downside: on Linux, Secret Service has no per-app gate, so A is no
stronger than B there, and it costs a D-Bus dependency and a larger crate tree.
On macOS, prompts depend on the binary's code identity; unsigned or rebuilt
binaries may re-prompt or be silently trusted (untested). If the owner mainly
works on Linux, or the prompt behavior fails testing, B is simpler for the same
real strength and A's cost is not justified.

## Unknowns to test before accepting

1. macOS: can a non-zbrain process under the same uid read the item with
   `security find-generic-password -w` without a prompt after the owner is
   logged in? Does a rebuilt zbrain re-prompt?
2. Linux: confirm any session-bus client reads an unlocked item without a
   prompt; behavior without a desktop session (SSH, CI).
3. Which `keyring` backend features give a stable, small tree on both targets.
4. Whether the key should be passphrase-protected, accepting a prompt on every
   approval.

## Open questions

- Should revoke and supersede transitions be signed in the same change (repro
  04), or as a follow-up?
- Is an ordering requirement on item 4 acceptable: verification lands first and
  is a no-op for `sig` until this ADR is accepted?

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
