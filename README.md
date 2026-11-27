# Componenta Auth Token

Purpose-separated, single-use bearer tokens for authentication flows.

The package is a reusable primitive for magic links, password reset and similar
one-time flows. It deliberately keeps one active token per subject and purpose.

Consumption preserves the token's recorded timeline when the wall clock moves
backwards: `usedAt` cannot precede `createdAt`. Creation time is not a not-before
restriction. Expiry checks still use the current clock and retain the original
expiry; the token remains single-use.

A claim that completes at or after expiry is rejected even when it began before
expiry. The consumed token cannot be reused after that rejection.

`DatabaseTokenManager` consumption is irreversible once committed. If a later
clock failure prevents returning the record, the exception propagates and the
token remains consumed; an exception is not a guarantee of rollback.

A lookup also checks expiry after its database read completes. Lookup does not
consume the token or change its state.

Security properties:

- credentials contain 32 CSPRNG bytes encoded as unpadded base64url;
- raw credentials are never persisted;
- persisted lookup values are SHA-256 hashes domain-separated by purpose;
- replacement is atomic on the unique `(subject_uuid, purpose)` key;
- consumption is atomic and single-use;
- purpose is part of lookup/consume, so a token issued for one flow cannot be
  accepted by another flow.
