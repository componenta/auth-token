# Changelog

## Unreleased (1.0.1)

- Reject a token that expires while its lookup is waiting for the database.
- Reject consumption that completes at or after expiry, including a delayed
  transaction commit. Such a token remains consumed and cannot be replayed.
- Keep the public API and schema unchanged.
