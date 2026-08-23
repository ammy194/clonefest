export interface EncryptionResult {
  ciphertext: string;
  iv: string;
  key: string;
}

export interface DecryptionResult {
  plaintext: string;
}

export interface ByteDecryptionResult {
  plaintextBytes: Uint8Array;
}

// Convert bytes to a guaranteed ArrayBuffer.
// This avoids TypeScript's ArrayBufferLike / SharedArrayBuffer
// compatibility issue with the Web Crypto API.
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

// Convert bytes to URL-safe base64 (chunked to avoid call-stack overflow on large payloads)
function toBase64Url(bytes: Uint8Array): string {
  // Process in chunks of 8192 to avoid exceeding the call-stack limit
  const chunks: string[] = [];
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    chunks.push(String.fromCharCode(...slice));
  }
  const binary = chunks.join('');
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Convert URL-safe base64 back to bytes
function fromBase64Url(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// Encrypt plaintext with random AES-256 key and 96-bit IV
export async function encryptSecret(
  plaintext: string,
): Promise<EncryptionResult> {
  const plaintextBytes = new TextEncoder().encode(plaintext);

  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    key,
    toArrayBuffer(plaintextBytes),
  );

  const keyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', key),
  );

  return {
    ciphertext: toBase64Url(new Uint8Array(ciphertextBuffer)),
    iv: toBase64Url(iv),
    key: toBase64Url(keyBytes),
  };
}

export async function encryptBytes(
  plaintextBytes: Uint8Array,
): Promise<EncryptionResult> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    key,
    toArrayBuffer(plaintextBytes),
  );

  const keyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', key),
  );

  return {
    ciphertext: toBase64Url(new Uint8Array(ciphertextBuffer)),
    iv: toBase64Url(iv),
    key: toBase64Url(keyBytes),
  };
}

// Decrypt ciphertext using key and IV
export async function decryptSecret(
  ciphertextB64: string,
  ivB64: string,
  keyB64: string,
): Promise<DecryptionResult> {
  const ciphertext = fromBase64Url(ciphertextB64);
  const iv = fromBase64Url(ivB64);
  const keyBytes = fromBase64Url(keyB64);

  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    key,
    toArrayBuffer(ciphertext),
  );

  return {
    plaintext: new TextDecoder().decode(plaintextBuffer),
  };
}

export async function decryptBytes(
  ciphertextB64: string,
  ivB64: string,
  keyB64: string,
): Promise<ByteDecryptionResult> {
  const ciphertext = fromBase64Url(ciphertextB64);
  const iv = fromBase64Url(ivB64);
  const keyBytes = fromBase64Url(keyB64);

  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
    },
    key,
    toArrayBuffer(ciphertext),
  );

  return {
    plaintextBytes: new Uint8Array(plaintextBuffer),
  };
}

// PBKDF2 key derivation for password protection
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations: number = 600_000,
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(passwordBytes),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(salt),
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey'],
  );
}

// Wrap the AES data key with a password-derived key
export async function wrapKeyWithPassword(
  dataKeyB64: string,
  password: string,
): Promise<{
  wrappedKey: string;
  wrapIv: string;
  salt: string;
  passwordVerifier: string;
}> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const kek = await deriveKeyFromPassword(password, salt);

  const dataKeyBytes = fromBase64Url(dataKeyB64);

  const dataKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(dataKeyBytes),
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const wrapIv = crypto.getRandomValues(new Uint8Array(12));

  const wrappedKeyBuffer = await crypto.subtle.wrapKey(
    'raw',
    dataKey,
    kek,
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(wrapIv),
    },
  );

  const verifierKeyBytes = new TextEncoder().encode(password);

  const verifierKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(verifierKeyBytes),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const verifierSaltText =
    'vaultdrop-verifier-' + toBase64Url(salt);

  const verifierSalt = new TextEncoder().encode(verifierSaltText);

  const verifierBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(verifierSalt),
      iterations: 600_000,
      hash: 'SHA-256',
    },
    verifierKey,
    256,
  );

  return {
    wrappedKey: toBase64Url(new Uint8Array(wrappedKeyBuffer)),
    wrapIv: toBase64Url(wrapIv),
    salt: toBase64Url(salt),
    passwordVerifier: toBase64Url(
      new Uint8Array(verifierBits),
    ),
  };
}

// Unwrap the data key using password and salt
export async function unwrapKeyWithPassword(
  wrappedKeyB64: string,
  wrapIvB64: string,
  saltB64: string,
  password: string,
): Promise<string> {
  const salt = fromBase64Url(saltB64);
  const wrapIv = fromBase64Url(wrapIvB64);
  const wrappedKey = fromBase64Url(wrappedKeyB64);

  const kek = await deriveKeyFromPassword(password, salt);

  const dataKey = await crypto.subtle.unwrapKey(
    'raw',
    toArrayBuffer(wrappedKey),
    kek,
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(wrapIv),
    },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const keyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', dataKey),
  );

  return toBase64Url(keyBytes);
}

export { toBase64Url, fromBase64Url };