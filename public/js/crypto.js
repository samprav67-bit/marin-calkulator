'use strict';

/**
 * Security Cipher v1
 *
 * Схема на стандартных примитивах WebCrypto:
 *   • у каждого устройства долговременная пара ECDH P-256;
 *   • для каждого сообщения генерируется одноразовая (ephemeral) пара ECDH P-256;
 *   • ECDH(ephemeral, получатель) -> HKDF-SHA256 -> AES-256-GCM;
 *   • открытый ключ эфемерной пары прикладывается к сообщению (ECIES).
 *
 * Каждое сообщение шифруется дважды: для собеседника и для себя,
 * чтобы история читалась на этом устройстве после перезагрузки.
 */

import * as idb from './idb.js';

const subtle = crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const INFO = 'security-messenger:v1:message';
const FILE_INFO = 'security-messenger:v1:file';
const IDENTITY_PREFIX = 'identity:';

export const b64 = {
  encode(bytes) {
    const view = new Uint8Array(bytes);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < view.length; i += chunk) {
      binary += String.fromCharCode.apply(null, view.subarray(i, i + chunk));
    }
    return btoa(binary);
  },
  decode(value) {
    const binary = atob(String(value));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },
};

export async function createIdentity() {
  const pair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const publicKey = b64.encode(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
  const jwk = await subtle.exportKey('jwk', pair.privateKey);
  const privateKey = await subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  return { publicKey, privateKey, createdAt: new Date().toISOString() };
}

/**
 * Ключи привязаны к аккаунту: на одном устройстве могут входить разные люди,
 * и у каждого должна быть своя пара ключей.
 */
export async function loadIdentity(userId) {
  if (!userId) throw new Error('missing_user');
  const stored = await idb.get(IDENTITY_PREFIX + userId);
  if (stored && stored.privateKey && stored.publicKey) return stored;
  return null;
}

export async function ensureIdentity(userId) {
  let identity = await loadIdentity(userId);
  if (!identity) {
    identity = await createIdentity();
    await idb.set(IDENTITY_PREFIX + userId, identity);
  }
  return identity;
}

export async function resetIdentity(userId) {
  await idb.remove(IDENTITY_PREFIX + userId);
}

async function deriveKey(sharedBits, salt, info) {
  const base = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function deriveShared(publicKeyB64, privateKey) {
  const publicKey = await subtle.importKey(
    'raw',
    b64.decode(publicKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  return subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
}

/** Шифрует объект для получателя с указанным публичным ключом. */
export async function encryptFor(recipientPublicKeyB64, value) {
  if (!recipientPublicKeyB64) throw new Error('missing_public_key');
  const ephemeral = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const shared = await deriveShared(recipientPublicKeyB64, ephemeral.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const key = await deriveKey(shared, salt, INFO);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    v: 1,
    epk: b64.encode(new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey))),
    salt: b64.encode(salt),
    iv: b64.encode(iv),
    ct: b64.encode(ciphertext),
  };
}

/** Расшифровывает сообщение собственным приватным ключом. */
export async function decryptWith(identity, payload) {
  if (!payload || payload.v !== 1) throw new Error('bad_payload');
  const shared = await deriveShared(payload.epk, identity.privateKey);
  const key = await deriveKey(shared, b64.decode(payload.salt), INFO);
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64.decode(payload.iv) },
    key,
    b64.decode(payload.ct),
  );
  return JSON.parse(decoder.decode(plaintext));
}

/** Шифрует бинарные данные случайным ключом AES-256-GCM. */
export async function encryptBytes(data) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { key: b64.encode(rawKey), iv: b64.encode(iv), data: new Uint8Array(ciphertext) };
}

export async function decryptBytes(keyB64, ivB64, data) {
  const key = await subtle.importKey('raw', b64.decode(keyB64), 'AES-GCM', false, ['decrypt']);
  return subtle.decrypt({ name: 'AES-GCM', iv: b64.decode(ivB64) }, key, data);
}

/** Отпечаток пары ключей — «код безопасности» для сверки голосом. */
export async function safetyNumber(publicKeyA, publicKeyB) {
  const pair = [publicKeyA || '', publicKeyB || ''].sort().join('|');
  const digest = new Uint8Array(await subtle.digest('SHA-256', encoder.encode(pair)));
  const groups = [];
  for (let i = 0; i < 12; i += 1) {
    const value = (digest[i * 2] << 8) | digest[i * 2 + 1];
    groups.push(String(value % 100000).padStart(5, '0'));
  }
  return groups;
}

/** Короткий id для локальных оптимистичных сообщений. */
export function randomId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return b64.encode(crypto.getRandomValues(new Uint8Array(16))).replace(/[^a-z0-9]/gi, '');
}

export { FILE_INFO };
