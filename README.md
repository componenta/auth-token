# Componenta Auth Token

Purpose-separated, single-use bearer tokens for authentication flows.

The package is a reusable primitive for magic links, password reset and similar
one-time flows. It deliberately keeps one active token per subject and purpose.

Security properties:

- credentials contain 32 CSPRNG bytes encoded as unpadded base64url;
- raw credentials are never persisted;
- persisted lookup values are SHA-256 hashes domain-separated by purpose;
- replacement is atomic on the unique `(subject_uuid, purpose)` key;
- consumption is atomic and single-use;
- purpose is part of lookup/consume, so a token issued for one flow cannot be
  accepted by another flow.
