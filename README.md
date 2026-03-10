# Capsara SDK - TypeScript

A **capsa** is a zero-knowledge encrypted envelope for securely exchanging files and data between multiple parties. Each capsa is sealed with its own encryption key and can only be opened by the parties explicitly authorized to access it. Capsara never sees your content, your keys, or your metadata.

## Features

- **AES-256-GCM** encryption with unique keys per capsa
- **RSA-4096-OAEP** key encryption for multi-party access
- **Compression** with gzip before encryption
- **Digital signatures** using RSA-SHA256 for sender authenticity
- **Encrypted subject, body, and structured data**
- **Batch sending** with automatic chunking

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
  email: 'you@example.com',
  password: '...'
});
```

### Set Private Key

After logging in, set your private key for signing and decryption. Generate and register your keypair using `generateKeyPair()` and `addPublicKey()`, then store the private key securely.

```typescript
// Your code to load the private key from secure storage (key vault, HSM, etc.)
const privateKey = loadPrivateKeyFromSecureStorage();

client.setPrivateKey(privateKey);
```

## Sending Capsas

Use the `CapsaBuilder` to create capsas with recipients and files. Always use `sendCapsas()` even for a single capsa since it handles encryption and batching efficiently.

```typescript
import { CapsaraClient, CapsaraError, FileInput } from '@capsara/sdk';

try {
  // Create a builder for each capsa you want to send
  const builder = await client.createCapsaBuilder();

  // Add recipients (can add multiple)
  builder.addRecipient('party_recipient1');
  builder.addRecipient('party_recipient2');

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
    console.error('Failed to send:', error.message);
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

The SDK automatically splits large batches to stay within server limits.

## Receiving Capsas

### List Capsas

```typescript
const response = await client.listCapsas({
  status: 'active',
  limit: 50
});

console.log(`Found ${response.capsas.length} capsas`);

for (const capsa of response.capsas) {
  console.log(`- ${capsa.id}: ${capsa.fileCount} files`);
  console.log(`  Created: ${capsa.createdAt}`);
  console.log(`  From: ${capsa.creatorId}`);
}

// Pagination
if (response.pagination.hasMore) {
  const nextPage = await client.listCapsas({
    after: response.pagination.nextCursor
  });
}
```

### Get Capsa and Download Files

```typescript
import fs from 'node:fs';

const capsa = await client.getCapsa('capsa_abc-123');

console.log('Subject:', capsa.subject);
console.log('Body:', capsa.body);
console.log('Structured data:', capsa.structured);

// Download each file
for (const file of capsa.files) {
  const { data, filename } = await client.downloadFile(capsa.packageId, file.id);
  fs.writeFileSync(`./downloads/${filename}`, data);
}
```

## Delegation

Capsara supports delegation for scenarios where a system acts on behalf of a party. For example, an agency management system (AMS) might process capsas on behalf of the agencies it serves. When a capsa is sent to a delegated recipient, the delegate receives its own RSA-encrypted copy of the master key. If the recipient also has a public key registered in the system, they receive their own encrypted copy as well. Otherwise, only the delegate can decrypt on their behalf.

If you're a delegate, the flow is identical to receiving. List your capsas and check the `actingFor` field on each one to see which party it belongs to. This lets you route the data to the correct recipient in your system.

```typescript
// Authenticate as the delegate (e.g., an AMS)
const client = new CapsaraClient('https://capsara-env-api-url.com');
await client.login({ email: 'ams@example.com', password: '...' });
client.setPrivateKey(loadPrivateKeyFromSecureStorage());

// List capsas (includes capsas for all parties you represent)
const response = await client.listCapsas();

for (const summary of response.capsas) {
  const capsa = await client.getCapsa(summary.id);

  // Check who this capsa is for
  if (capsa.actingFor) {
    console.log(`Capsa ${summary.id} is for agency ${capsa.actingFor}`);
    routeToAgency(capsa.actingFor, capsa);
  }

  // Download and process files
  for (const file of capsa.files) {
    const { data, filename } = await client.downloadFile(summary.id, file.id);
    processFile(capsa.actingFor, filename, data);
  }
}
```

## Encryption

Every capsa is protected by a unique AES-256-GCM symmetric key (the "master key") generated at send time. Files and metadata (subject, body, and structured data) are each encrypted with this master key using a fresh random IV, producing authenticated ciphertext that guarantees both confidentiality and tamper detection. The master key itself is then encrypted once per authorized party and any authorized delegates using their RSA-4096 public key with OAEP-SHA256 padding, so only the holder of the corresponding private key can recover it. Each file is independently hashed with SHA-256 before encryption, and these hashes along with all IVs are bound into a canonical string that the sender signs using RS256 (RSA-SHA256 in JWS format). Recipients and the server validate this signature against the sender's public key before trusting any content, ensuring both authenticity and integrity of the entire capsa. Key fingerprints are SHA-256 hashes of the public key PEM, providing a compact identifier for key verification. Files are gzip-compressed before encryption by default to reduce storage and transfer costs. All encryption, decryption, signing, and verification happen locally in the SDK. Capsara's servers only ever store ciphertext and cannot read your files, your metadata, or your keys.

## Private Key Security

Your private key is the sole point of access to every capsa encrypted for you. Capsara uses zero-knowledge encryption: your private key never leaves your environment, is never transmitted to Capsara's servers, and is never stored by Capsara. There is no recovery mechanism, no master backdoor, and no support override. If your private key is lost, every capsa encrypted for your party becomes permanently inaccessible. No one (not Capsara, not the sender, not an administrator) can recover your data without your private key.

You are fully responsible for your private key's lifecycle: generation, secure storage, and backup. Store it in a cloud key vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault), a hardware security module, or at minimum an encrypted secrets manager. Never store it in source code, configuration files, or logs. Back it up to a secondary secure location so that a single infrastructure failure does not result in permanent data loss.

The SDK provides a `rotateKey()` method that generates a new RSA-4096 key pair and registers the new public key with Capsara. New capsas sent to you will be encrypted with your new key. However, capsas are immutable once created and their keychain and encrypted contents never change. Existing capsas remain accessible only with the private key that was active when they were created. Keep prior private keys available for as long as you need access to capsas encrypted under them.

## API Reference

| Method | Description |
|--------|-------------|
| `CapsaraClient.generateKeyPair()` | Generate an RSA-4096 key pair (static) |
| `login(credentials)` | Authenticate with email and password |
| `logout()` | Log out and clear cached data |
| `setPrivateKey(privateKey)` | Set the private key for signing and decryption |
| `createCapsaBuilder()` | Create a `CapsaBuilder` pre-loaded with server limits |
| `sendCapsas(builders)` | Encrypt and send one or more capsas |
| `getCapsa(capsaId)` | Fetch and decrypt a capsa |
| `listCapsas(filters?)` | List capsas with optional filters |
| `deleteCapsa(capsaId)` | Soft-delete a capsa |
| `downloadFile(capsaId, fileId)` | Download and decrypt a file |
| `getAuditEntries(capsaId)` | Get audit trail entries |
| `addPublicKey(key, fingerprint)` | Register a new public key |
| `rotateKey()` | Generate and register a new key pair |
| `getKeyHistory()` | Get previous public keys |
| `getLimits()` | Get server-enforced limits |
| `destroy()` | Release resources and clear keys |

## License

Capsara SDK License. See [LICENSE](./LICENSE) for details.
