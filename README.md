# Capsara SDK - TypeScript

A **capsa** is a zero-knowledge encrypted envelope for securely exchanging files and data between multiple parties. Each capsa is sealed with its own encryption key and can only be opened by the parties explicitly authorized to access it. Capsara never sees your content, your keys, or your metadata.

## Features

- **AES-256-GCM** encryption with unique keys per capsa
- **RSA-4096-OAEP** key encryption for multi-party access
- **Compression** with gzip before encryption
- **Digital signatures** using RSA-SHA256 for sender authenticity
- **Encrypted subject, body, and structured data**
- **Batch sending** with automatic chunking

## Requirements

- Node.js 20 or later
- The package is published as an ES module

## Installation

```bash
npm install @capsara/sdk
```

## Initialize the Client

```typescript
import { CapsaraClient } from '@capsara/sdk';

const client = new CapsaraClient('https://capsara-env-api-url.com');
```

## Authentication

Authentication requires two steps: login with your credentials, then set your private key for cryptographic operations.

### Login

```typescript
await client.login({
  partyId: 'party_...',
  password: '...'
});
```

### Set Private Key

After logging in, set your private key for signing and decryption. Generate and register your keypair using `CapsaraClient.generateKeyPair()` and `addPublicKey()`, then store the private key securely.

```typescript
// Your code to load the private key from secure storage (key vault, HSM, etc.)
const privateKey = loadPrivateKeyFromSecureStorage();

client.setPrivateKey(privateKey);
```

## Sending Capsas

Use a capsa builder to create capsas with recipients and files. Always use `sendCapsas()` even for a single capsa since it handles encryption and batching efficiently.

```typescript
import { CapsaraClient, CapsaraError, FileInput } from '@capsara/sdk';

try {
  // Create a builder for each capsa you want to send
  const builder = await client.createCapsaBuilder();

  // Add the recipient (one per capsa; their delegates are added automatically)
  builder.addRecipient('party_recipient1');

  // Add files from path or buffer
  builder.addFile(FileInput.fromPath('./documents/policy.pdf'));
  builder.addFile(FileInput.fromBuffer(
    Buffer.from('Policy data here'),
    'policy-data.txt'
  ));

  // Add optional metadata
  builder.withSubject('Policy Documents - Q1 2025');
  builder.withBody('Please review the attached policy documents.');
  builder.withStructured({
    policyNumber: 'POL-12345',
    effectiveDate: '2025-01-01'
  });

  // Set expiration
  builder.withExpiration(new Date(Date.now() + 90 * 24 * 60 * 60 * 1000));

  // Send
  const result = await client.sendCapsas([builder]);
  console.log(`Sent ${result.successful} capsa(s)`);

  if (result.failed > 0) {
    console.error(`${result.failed} capsas failed to send`);
  }
} catch (error) {
  if (error instanceof CapsaraError) {
    console.error(`Failed to send: ${error.code} ${error.message}`);
  } else {
    throw error;
  }
}
```

A **capsa** maps one-to-one with a *matter*, which is a unique combination of sender, recipient, client, and action. You can send multiple capsas in one call:

```typescript
const matter1 = await client.createCapsaBuilder();
matter1
  .addRecipient('party_org_b')
  .withSubject('Client 1 - New Home Policy')
  .addFile(FileInput.fromPath('./policy.pdf'));

const matter2 = await client.createCapsaBuilder();
matter2
  .addRecipient('party_org_b')
  .withSubject('Client 1 - Auto Endorsement')
  .withBody('Endorsement effective 3/1. No documents required.');

await client.sendCapsas([matter1, matter2]);
```

Each capsa goes to exactly one recipient, its principal. Multi-party access comes through that recipient's delegates, which the SDK adds automatically, each with its own encrypted key and acting for the recipient. A second `addRecipient()` on the same builder throws, and a builder with no recipient is rejected before anything is sent. To send to yourself, pass your own party ID; your delegates are then included. To reach several recipients, create one builder per recipient and send them together in one batch:

```typescript
const recipients = ['party_recipient1', 'party_recipient2'];

const builders = await Promise.all(recipients.map(async (recipient) => {
  const builder = await client.createCapsaBuilder();
  return builder
    .addRecipient(recipient)
    .withSubject('Policy Documents - Q1 2025')
    .addFile(FileInput.fromPath('./documents/policy.pdf'))
    .withExpiration(new Date(Date.now() + 90 * 24 * 60 * 60 * 1000));
}));

const result = await client.sendCapsas(builders);
for (const error of result.errors ?? []) {
  // code is the reason the capsa was rejected, e.g. DELEGATE_PRINCIPAL_MISMATCH
  console.error(`Capsa ${error.index} failed: ${error.error} (${error.code})`);
}
```

The builder class is not exported by name. Let TypeScript infer it from `createCapsaBuilder()`, or name it as `Awaited<ReturnType<CapsaraClient['createCapsaBuilder']>>`.

The SDK automatically splits large batches to stay within server limits. Call `getLimits()` to read the current limits.

## Receiving Capsas

### List Capsas

```typescript
const response = await client.listCapsas({
  status: 'active',
  limit: 50
});

console.log(`Found ${response.capsas.length} capsas`);

for (const capsa of response.capsas) {
  console.log(`- ${capsa.id} (${capsa.status ?? 'unknown'})`);
  console.log(`  Created: ${capsa.createdAt}`);
  console.log(`  From: ${capsa.creator}`);
}

// Pagination
if (response.pagination.hasMore) {
  const nextPage = await client.listCapsas({
    after: response.pagination.nextCursor
  });
}
```

### Get Capsa and Download Files

A file's `filename` comes from the sender and is untrusted, so write each file under a directory you choose using `safeFilename`, which is always a single, safe path segment (see `sanitizeFilename` for the rules):

```typescript
import fs from 'node:fs';
import path from 'node:path';

const downloadDir = './downloads';

const capsa = await client.getCapsa('capsa_abc-123');

console.log('Subject:', capsa.subject);
console.log('Body:', capsa.body);
console.log('Structured data:', capsa.structured);

// Download each file
for (const file of capsa.files) {
  const { data, safeFilename } = await client.downloadFile(capsa.id, file.fileId);
  fs.writeFileSync(path.join(downloadDir, safeFilename), data);
}
```

## Delegation

Capsara supports delegation for scenarios where a system acts on behalf of a party. For example, an agency management system (AMS) might process capsas on behalf of the agencies it serves. When a capsa is sent to a delegated recipient, the delegate receives its own RSA-encrypted copy of the master key. If the recipient also has a public key registered in the system, they receive their own encrypted copy as well. Otherwise, only the delegate can decrypt on their behalf.

If you're a delegate, the flow is identical to receiving. To see which party a capsa belongs to, find your own entry in the capsa's keychain: its `actingFor` field lists the party IDs you act for on that capsa. This lets you route the data to the correct recipient in your system.

```typescript
// Authenticate as the delegate (e.g., an AMS)
const client = new CapsaraClient('https://capsara-env-api-url.com');
const auth = await client.login({ partyId: 'party_...', password: '...' });
client.setPrivateKey(loadPrivateKeyFromSecureStorage());
const myPartyId = auth.party.id;

// List capsas (includes capsas for all parties you represent)
const response = await client.listCapsas();

for (const summary of response.capsas) {
  const capsa = await client.getCapsa(summary.id);

  // Check who this capsa is for
  const myEntry = capsa.keychain.keys.find((entry) => entry.party === myPartyId);
  const agencyId = myEntry?.actingFor?.[0];
  if (agencyId) {
    console.log(`Capsa ${summary.id} is for agency ${agencyId}`);
    routeToAgency(agencyId, capsa);
  }

  // Download and process files
  for (const file of capsa.files) {
    const { data, safeFilename } = await client.downloadFile(summary.id, file.fileId);
    processFile(agencyId, safeFilename, data);
  }
}
```

## Error Handling

Every SDK error is a `CapsaraError`. The subclasses `CapsaraAuthError`, `CapsaraCapsaError`, `CapsaraAuditError` and `CapsaraAccountError` tell you which area failed.

```typescript
import { CapsaraAuthError, CapsaraCapsaError, CapsaraError } from '@capsara/sdk';

try {
  const capsa = await client.getCapsa('capsa_abc-123');
} catch (error) {
  if (error instanceof CapsaraAuthError) {
    console.error(`Auth error: ${error.message} (${error.code})`);
  } else if (error instanceof CapsaraCapsaError) {
    console.error(`Capsa error: ${error.message} (${error.code})`);
  } else if (error instanceof CapsaraError) {
    console.error(`Error: ${error.message} (${error.code})`);
  } else {
    throw error;
  }
}
```

Every `CapsaraError` exposes:

- `code`: the API error code exactly as the server sent it (e.g. `ENVELOPE_NOT_FOUND`, `RATE_LIMIT_EXCEEDED`), or an SDK code for client-side failures. A response without a usable error body gets `HTTP_<status>`.
- `statusCode`: the HTTP status (0 for client-side failures).
- `details`: the server's details as sent, when provided.
- `retryAfter`: seconds to wait on 429/503, when provided.
- `requestId`: the server request ID, when provided.

Expired and deleted capsas fail with `CapsaraCapsaError` status 410 and code `ENVELOPE_EXPIRED` or `ENVELOPE_DELETED`. Signature problems fail before decryption with `SIGNATURE_KEY_MISSING`, `SIGNATURE_KEY_MISMATCH` or `SIGNATURE_VERIFICATION_FAILED`. A capsa encrypted to a key you have not configured fails with `PRIVATE_KEY_NOT_AVAILABLE`.

## Encryption

Every capsa is protected by its own AES-256-GCM key (the "master key"), generated in the SDK at send time. Files, filenames, and the subject, body and structured data are each encrypted with the master key under a fresh random IV, so any change to the ciphertext is detected on decryption. Files are gzip-compressed before encryption by default. The master key is then encrypted for the sender, the recipient and each of the recipient's delegates with their RSA-4096 public key using OAEP with SHA-256, so only the holder of a matching private key can recover it. The sender signs the capsa with RS256 (RSA-SHA256 in JWS format) over a canonical string that binds the capsa ID, its total size, the key-encryption algorithm, the sender's party ID, the fingerprint of the sender's public key, the SHA-256 hash of each encrypted file, every file and filename IV, and the IVs of the subject, body and structured data. The server checks this signature at upload. On receive, the SDK checks the sender's public key against the sender's keychain fingerprint, rebuilds the canonical string from the capsa it received, and verifies the signature before decrypting anything, so a signature cannot be moved to another capsa or key. Key fingerprints are lowercase hex SHA-256 hashes of the DER-encoded SubjectPublicKeyInfo, so PEM formatting does not change them. All encryption, decryption, signing, and verification happen locally in the SDK. Capsara's servers only ever store ciphertext and cannot read your files, your metadata, or your keys.

## Private Key Security

Your private key is the sole point of access to every capsa encrypted for you. Capsara uses zero-knowledge encryption: your private key never leaves your environment, is never transmitted to Capsara's servers, and is never stored by Capsara. There is no recovery mechanism, no master backdoor, and no support override. If your private key is lost, every capsa encrypted for your party becomes permanently inaccessible. No one (not Capsara, not the sender, not an administrator) can recover your data without your private key.

You are fully responsible for your private key's lifecycle: generation, secure storage, and backup. Store it in a cloud key vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), a hardware security module, or at minimum an encrypted secrets manager. Never store it in source code, configuration files, or logs. Back it up to a secondary secure location so that a single infrastructure failure does not result in permanent data loss.

The SDK provides a `rotateKey()` method that generates a new RSA-4096 key pair and registers the new public key with Capsara. New capsas sent to you will be encrypted with your new key. However, capsas are immutable once created and their keychain and encrypted contents never change. Existing capsas remain accessible only with the private key that was active when they were created. Keep prior private keys available for as long as you need access to capsas encrypted under them.

Pass `onKeyPairGenerated` to `rotateKey()` to store the new key pair before it is registered, so a lost response cannot lose the key; if the callback throws, nothing is registered. After a successful rotation the client uses the new private key and keeps the previous one for decrypting older capsas. After a restart, give the client your older keys with `addPreviousPrivateKey()` or the `previousPrivateKeys` client option. The SDK picks the key whose fingerprint matches your keychain entry; if none matches it throws `PRIVATE_KEY_NOT_AVAILABLE`.

## API Reference

| Method | Description |
|--------|-------------|
| `CapsaraClient.generateKeyPair()` | Generate an RSA-4096 key pair (static, async) |
| `login(credentials)` | Authenticate with party ID and password |
| `logout()` | Clear local tokens and cached data, then revoke the session (throws `CapsaraAuthError` if the server does not confirm) |
| `isAuthenticated()` | Check whether the client has an access token |
| `setPrivateKey(privateKey)` | Set the private key for signing and decryption |
| `addPreviousPrivateKey(privateKey)` | Keep a rotated-out private key for older capsas |
| `createCapsaBuilder()` | Create a capsa builder pre-loaded with server limits |
| `sendCapsas(builders)` | Encrypt and send one or more capsas |
| `getCapsa(capsaId)` | Fetch, verify and decrypt a capsa |
| `listCapsas(filters?)` | List capsas with optional filters |
| `deleteCapsa(capsaId)` | Soft-delete a capsa |
| `downloadFile(capsaId, fileId)` | Download and decrypt a file |
| `getAuditEntries(capsaId, filters?)` | Get audit trail entries |
| `createAuditEntry(capsaId, entry)` | Add an audit entry (`log` or `processed`) |
| `getCurrentPublicKey()` | Get your current registered public key |
| `addPublicKey(key, fingerprint, reason?)` | Register a new public key |
| `rotateKey(options?)` | Generate and register a new key pair, then switch to it |
| `getKeyHistory()` | Get the fingerprints and rotation dates of previous keys |
| `getLimits()` | Get server-enforced limits |
| `clearCache()` | Clear cached master keys |
| `destroy()` | Release resources and clear keys |

## Support

Email support@tessarai.com.

## License

Capsara SDK License. See [LICENSE](./LICENSE) for details.

Copyright (c) 2024-2026 Tessarai, LLC and Laird Rixford. All rights reserved.
