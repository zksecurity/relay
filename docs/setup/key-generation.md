# Ceremony identity key generation

Use this procedure for every participant, coordinator, auditor, release signer,
or other role that needs an Ed25519 ceremony identity. Generate the key on the
trusted machine that will hold it. Relay, the coordination website, Google
login, and the coordinator must never receive the private file.

## 1. Authenticate the ceremony tools first

Obtain and verify the approved ceremony kit as described in
[docs/INSTALL.md](INSTALL.md). Have setup create the receipt that later
commands use to authenticate the installed Relay and `mpc-ceremony` binaries:

```sh
CEREMONY_TOOLS_ROOT=/opt/ceremony-tools
TOOL_IDENTITY_RECEIPT=$CEREMONY_TOOLS_ROOT/tool-identity-receipt.env

cd "$CEREMONY_TOOLS_ROOT/ceremony-kit"
./setup verify --receipt-out "$TOOL_IDENTITY_RECEIPT"
```

Stop if the archive digest or setup verification fails. Do not generate a
production identity with a binary downloaded or built through an unapproved
path.

## 2. Generate the key and public identity

If your role is using the Docker-packaged tools, the same command can be run
inside the network-disabled key-generation image through the saved launcher;
see [GUIDED_SETUP.md](GUIDED_SETUP.md). The key remains in your protected
mounted directory. The direct command below is the explicit reference form.

Choose the stable identity ID assigned during onboarding. It may contain only
lowercase letters, digits, `-`, `_`, `.`, or `:`. The display name is public
and will appear in ceremony records.

```sh
IDENTITY_ID=participant-03
PRIVATE_ROOT=/secure/ceremony-identities
PUBLIC_ROOT=/secure/ceremony-public

install -d -m 0700 "$PRIVATE_ROOT" "$PUBLIC_ROOT"

mpc-ceremony identity generate \
  --identity-id "$IDENTITY_ID" \
  --display-name "Participant Three" \
  --private-key-out "$PRIVATE_ROOT/$IDENTITY_ID.private.hex" \
  --public-identity-out "$PUBLIC_ROOT/$IDENTITY_ID.identity.json"
```

The command uses the operating-system cryptographic random source and creates
both files without overwriting anything:

- `*.private.hex` is the secret 32-byte Ed25519 seed in proof-tool's accepted
  format, created with mode `0600`;
- `*.identity.json` is canonical public JSON containing the identity ID,
  display name, Ed25519 public key, SHA-256 fingerprint, and automatically
  derived key ID.

The key ID is generated as `ed25519:` followed by the SHA-256 digest of the
public key. There is no separate key-ID generation step and no value to invent
or copy by hand.

Do not use `ssh-keygen`, OpenSSL, GPG, or a generic PEM file for this role key;
their private-key encodings are not the file format accepted by
`mpc-ceremony`. Never paste the private bytes into a browser, chat, ticket,
shell command, or checklist.

## 3. Send only the public document

Send the complete `*.identity.json` file to the coordinator through the agreed
authenticated onboarding channel. The coordinator or coordination UI imports
that public object into the proposed roster. Do not send the private file.

The command's terminal output and public identity file are secret-free and may
be retained as onboarding evidence. Protect the private file according to the
ceremony's key-custody plan; losing it prevents the role from signing its later
ceremony actions.

After the coordinator signs the ceremony definition, `relay ceremony
init-config` authenticates the approved tool binaries from the setup receipt,
asks proof-tool to derive the public key from the local private file, and
matches it to the signed identity, key ID, fingerprint, and phase positions.
Your remaining human decision is whether the authenticated mode and assignment
match what you agreed to.
