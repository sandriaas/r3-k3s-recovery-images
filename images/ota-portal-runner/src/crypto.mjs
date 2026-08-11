import { webcrypto } from 'node:crypto';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function deriveKey(secret, usages) {
  const material = await webcrypto.subtle.digest('SHA-256', encoder.encode(secret));
  return webcrypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, usages);
}

export async function encryptSecret(plaintext, secret) {
  const key = await deriveKey(secret, ['encrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext),
  );
  return Object.freeze({
    secretEnc: Buffer.from(ciphertext).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
  });
}

export async function decryptSecret(secretEnc, iv, secret) {
  const key = await deriveKey(secret, ['decrypt']);
  const plaintext = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(iv, 'base64') },
    key,
    Buffer.from(secretEnc, 'base64'),
  );
  return decoder.decode(plaintext);
}
