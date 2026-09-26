# ADR 0010: Three identities; app login is not a key

1. **The user unlocking Anvil** (local profile: passphrase, recovery key or
   OS keychain; optionally a linked provider identity).
2. **The client identity Anvil presents** to an API or gateway (auth
   profiles, client certificates).
3. **The gateway's own identity** towards its backend. Anvil can observe it
   only through gateway evidence and can never change it.

- A provider identity (Google, GitHub or Facebook, once registered) is bound
  to a profile for identity only. It never derives or wraps the data key.
  An optional policy can require a fresh provider login before local unlock;
  the offline path is then the recovery key.
- Real providers stay unavailable in builds that lack owner-registered
  client ids and redirect URIs. No client ids are invented, and no secrets
  are embedded in the app.
- Diagnostics keep identities 2 and 3 apart. A backend mTLS failure behind
  the gateway is never blamed on the user's client certificate.
