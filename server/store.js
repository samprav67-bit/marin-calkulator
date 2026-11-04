'use strict';

/**
 * Простое хранилище на JSON-файле с атомарной записью.
 * Содержимое db.json шифруется на диске AES-256-GCM.
 *
 * Ключ шифрования:
 *  - берётся из переменной окружения DB_ENCRYPTION_KEY (32 байта, base64), либо
 *  - автоматически генерируется и сохраняется в data/db.key с правами 0600.
 *
 * Без внешних зависимостей: сервер запускается одной командой `node server.js`.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ROOT } = require('./paths');

const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const FILES_DIR = path.join(DATA_DIR, 'files');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const KEY_FILE = path.join(DATA_DIR, 'db.key');

fs.mkdirSync(FILES_DIR, { recursive: true });
fs.mkdirSync(AVATARS_DIR, { recursive: true });

// --- Ключ шифрования базы -------------------------------------------------

function loadKey() {
  const fromEnv = process.env.DB_ENCRYPTION_KEY;
  if (fromEnv) {
    const key = Buffer.from(fromEnv, 'base64');
    if (key.length !== 32) {
      throw new Error('DB_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits)');
    }
    return key;
  }

  // Автоматический ключ рядом с базой. Права 0600, чтобы файл не читался другими пользователями.
  let raw;
  try {
    raw = fs.readFileSync(KEY_FILE, 'utf8');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  if (raw !== undefined) {
    const key = Buffer.from(raw.trim(), 'base64');
    if (key.length !== 32) {
      throw new Error(
        `Файл ${KEY_FILE} повреждён: ключ должен быть base64 на 32 байта. ` +
        'Восстановите его из резервной копии — без ключа база не расшифруется.',
      );
    }
    return key;
  }

  // Ключа нет. Если рядом уже лежит зашифрованная база — новый ключ её не откроет,
  // поэтому не создаём его и не рискуем перезаписать данные.
  let existingDb = '';
  try {
    existingDb = fs.readFileSync(DB_FILE, 'utf8');
  } catch {
    /* базы ещё нет — это первый запуск */
  }
  if (existingDb.trim() && !existingDb.trimStart().startsWith('{')) {
    throw new Error(
      `Файл ${DB_FILE} зашифрован, но ключ ${KEY_FILE} не найден. ` +
      'Восстановите db.key из резервной копии (или задайте DB_ENCRYPTION_KEY).',
    );
  }

  const key = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, key.toString('base64'), { mode: 0o600 });
  try {
    fs.chmodSync(KEY_FILE, 0o600);
  } catch {
    /* Windows может игнорировать POSIX-права */
  }
  console.warn('[store] создан новый ключ шифрования базы:', KEY_FILE);
  console.warn('[store] сохраните его: без него db.json не расшифровать.');
  return key;
}

const ENCRYPTION_KEY = loadKey();

function encryptDb(plaintext) {
  const iv = crypto.randomBytes(12); // nonce для GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Формат файла: iv(12) + tag(16) + ciphertext, всё в base64
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptDb(ciphertextB64) {
  const data = Buffer.from(ciphertextB64, 'base64');
  if (data.length < 28) throw new Error('db file too short');
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const encrypted = data.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function emptyDb() {
  return {
    meta: { createdAt: new Date().toISOString(), version: 1 },
    users: {},
    sessions: {},
    chats: {},
    messages: {},
    files: {},
    codes: {},
    accessChallenges: {},
  };
}

let db;
let migrated = false;
let dbSize = 0;
try {
  dbSize = fs.statSync(DB_FILE).size;
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
  dbSize = 0;
}

if (dbSize > 0) {
  const raw = fs.readFileSync(DB_FILE, 'utf8');
  try {
    db = JSON.parse(decryptDb(raw));
  } catch {
    try {
      // Возможно, это старый незашифрованный db.json — импортируем и зашифруем при сохранении.
      db = JSON.parse(raw);
      migrated = true;
    } catch {
      throw new Error(
        `Не удалось расшифровать ${DB_FILE}. ` +
        'Проверьте, что data/db.key (или DB_ENCRYPTION_KEY) тот же, что при создании базы. ' +
        'Не удаляйте db.key — без него данные не восстановить.',
      );
    }
  }
} else {
  db = emptyDb();
}

for (const key of Object.keys(emptyDb())) {
  if (!db[key]) db[key] = emptyDb()[key];
}

// Одноразовые коды и ожидающие входы не должны переживать перезапуск сервера.
let ephemeralCleared = false;
if (Object.keys(db.codes).length) {
  db.codes = {};
  ephemeralCleared = true;
}
if (Object.keys(db.accessChallenges).length) {
  db.accessChallenges = {};
  ephemeralCleared = true;
}

let timer = null;
let dirty = migrated || ephemeralCleared;
let writing = false;

if (migrated) {
  console.log('[store] найден незашифрованный db.json — он будет зашифрован при первом сохранении');
  setTimeout(flush, 50);
} else if (ephemeralCleared) {
  setTimeout(flush, 50);
}

function flush() {
  timer = null;
  if (!dirty || writing) return;
  dirty = false;
  writing = true;
  try {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, encryptDb(JSON.stringify(db)));
    fs.renameSync(tmp, DB_FILE);
  } catch (err) {
    dirty = true;
    console.error('[store] не удалось зашифровать и сохранить базу:', err.message);
  } finally {
    writing = false;
  }
}

function save() {
  dirty = true;
  if (!timer) timer = setTimeout(flush, 120);
}

function flushSync() {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (!dirty) return;
  dirty = false;
  try {
    fs.writeFileSync(DB_FILE, encryptDb(JSON.stringify(db)));
  } catch (err) {
    console.error('[store] не удалось зашифровать и сохранить базу:', err.message);
  }
}

process.on('exit', flushSync);
process.on('SIGINT', () => {
  flushSync();
  process.exit(0);
});
process.on('SIGTERM', () => {
  flushSync();
  process.exit(0);
});

module.exports = {
  db,
  save,
  flush,
  flushSync,
  DATA_DIR,
  FILES_DIR,
  AVATARS_DIR,
  DB_FILE,
  KEY_FILE,
};
