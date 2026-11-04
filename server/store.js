'use strict';

/**
 * Хранилище состояния мессенджера.
 *
 * Локальный запуск (.exe / node server.js): зашифрованный JSON-файл data/db.json,
 * файлы и аватарки лежат рядом в data/.
 *
 * Облачный запуск (Vercel): состояние хранится в Turso (LibSQL), файлы — в
 * приватном Vercel Blob. Наружу Turso видит только AES-256-GCM шифротекст.
 *
 * Ключ шифрования:
 *  - DB_ENCRYPTION_KEY (32 байта, base64) — обязателен в облаке;
 *  - локально при отсутствии переменной ключ создаётся в data/db.key.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Readable } = require('stream');
const { ROOT } = require('./paths');

const CLOUD = Boolean(process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN);
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const FILES_DIR = path.join(DATA_DIR, 'files');
const AVATARS_DIR = path.join(DATA_DIR, 'avatars');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const KEY_FILE = path.join(DATA_DIR, 'db.key');

if (!CLOUD) {
  fs.mkdirSync(FILES_DIR, { recursive: true });
  fs.mkdirSync(AVATARS_DIR, { recursive: true });
}

/* ------------------------------ ключ шифрования --------------------------- */

function loadKey() {
  const fromEnv = process.env.DB_ENCRYPTION_KEY;
  if (fromEnv) {
    const key = Buffer.from(fromEnv, 'base64');
    if (key.length !== 32) {
      throw new Error('DB_ENCRYPTION_KEY must decode to exactly 32 bytes (256 bits)');
    }
    return key;
  }

  if (CLOUD) {
    throw new Error('DB_ENCRYPTION_KEY is required when Turso storage is enabled');
  }

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
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
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

/* ---------------------------------- модель -------------------------------- */

function emptyDb() {
  return {
    meta: { createdAt: new Date().toISOString(), version: 2, eventSeq: 0 },
    users: {},
    sessions: {},
    chats: {},
    messages: {},
    files: {},
    codes: {},
    accessChallenges: {},
    events: [],
  };
}

function ensureShape(target) {
  const base = emptyDb();
  for (const key of Object.keys(base)) {
    if (target[key] === undefined || target[key] === null) target[key] = base[key];
  }
  if (!target.meta || typeof target.meta !== 'object') target.meta = base.meta;
  if (!Number.isFinite(target.meta.eventSeq)) target.meta.eventSeq = 0;
  if (!Array.isArray(target.events)) target.events = [];
  if (target.events.length > 800) target.events = target.events.slice(-800);
}

let db;
let migrated = false;
let dbSize = 0;

if (!CLOUD) {
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
} else {
  db = emptyDb();
}

ensureShape(db);

// Одноразовые коды и ожидающие входы не должны переживать перезапуск сервера.
if (!CLOUD) {
  let ephemeralCleared = false;
  if (Object.keys(db.codes).length) {
    db.codes = {};
    ephemeralCleared = true;
  }
  if (Object.keys(db.accessChallenges).length) {
    db.accessChallenges = {};
    ephemeralCleared = true;
  }
  if (migrated || ephemeralCleared) {
    setTimeout(() => {
      save();
    }, 50);
  }
}

/* ------------------------------ локальное хранилище ----------------------- */

let timer = null;
let dirty = migrated;
let writing = false;

function flushLocal() {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
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

function saveLocal() {
  dirty = true;
  if (!timer) timer = setTimeout(flushLocal, 120);
}

/* -------------------------------- облако (Turso) -------------------------- */

let client = null;
let initPromise = null;
let currentLockToken = null;

function cloudClient() {
  if (client) return client;
  if (!CLOUD) throw new Error('Turso storage is not configured');
  const { createClient } = require('@libsql/client');
  client = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
  });
  return client;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function loadCloud() {
  const result = await cloudClient().execute(
    'SELECT data FROM security_state WHERE id = 1',
  );
  const row = result.rows && result.rows[0];
  const raw = row && row.data ? String(row.data) : '';
  if (!raw) {
    applyDb(emptyDb());
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(decryptDb(raw));
  } catch {
    throw new Error(
      'Не удалось расшифровать облачную базу. Проверьте DB_ENCRYPTION_KEY — ' +
      'без прежнего ключа данные восстановить нельзя.',
    );
  }
  applyDb(parsed);
}

function applyDb(next) {
  for (const key of Object.keys(db)) delete db[key];
  Object.assign(db, next);
  ensureShape(db);
}

async function init() {
  if (!CLOUD) return;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const sql = cloudClient();
    await sql.execute(
      'CREATE TABLE IF NOT EXISTS security_state (' +
      'id INTEGER PRIMARY KEY CHECK (id = 1), ' +
      'data TEXT NOT NULL DEFAULT \'\', ' +
      'version INTEGER NOT NULL DEFAULT 0, ' +
      'lock_token TEXT, ' +
      'lock_until INTEGER' +
      ')',
    );
    await sql.execute(
      'INSERT OR IGNORE INTO security_state (id, data, version) VALUES (1, \'\', 0)',
    );
    await loadCloud();
  })().catch((err) => {
    initPromise = null;
    throw err;
  });
  return initPromise;
}

async function refresh() {
  if (!CLOUD) return;
  await init();
  await loadCloud();
}

async function acquireLock() {
  const sql = cloudClient();
  const token = crypto.randomBytes(16).toString('hex');
  const ttl = 45000;
  const started = Date.now();

  while (Date.now() - started < 20000) {
    const now = Date.now();
    const result = await sql.execute({
      sql:
        'UPDATE security_state SET lock_token = ?, lock_until = ? ' +
        'WHERE id = 1 AND (lock_token IS NULL OR lock_until < ?)',
      args: [token, now + ttl, now],
    });
    if (result.rowsAffected > 0) return token;
    await sleep(120 + Math.floor(Math.random() * 180));
  }

  throw Object.assign(new Error('busy'), {
    status: 503,
    userMessage: 'Сервер занят, попробуйте ещё раз.',
  });
}

async function releaseLock(token) {
  if (!CLOUD || !token) return;
  try {
    await cloudClient().execute({
      sql:
        'UPDATE security_state SET lock_token = NULL, lock_until = NULL ' +
        'WHERE id = 1 AND lock_token = ?',
      args: [token],
    });
  } catch (err) {
    console.error('[store] не удалось снять блокировку:', err.message);
  }
}

async function flushCloud() {
  if (!dirty) return;
  let token = currentLockToken;
  let owned = false;
  if (!token) {
    token = await acquireLock();
    currentLockToken = token;
    owned = true;
  }

  const encrypted = encryptDb(JSON.stringify(db));
  const result = await cloudClient().execute({
    sql:
      'UPDATE security_state SET data = ?, version = version + 1, ' +
      'lock_token = NULL, lock_until = NULL ' +
      'WHERE id = 1 AND lock_token = ?',
    args: [encrypted, token],
  });
  if (result.rowsAffected === 0) {
    dirty = true;
    throw Object.assign(new Error('state_conflict'), {
      status: 503,
      userMessage: 'Не удалось сохранить изменения, попробуйте ещё раз.',
    });
  }
  dirty = false;

  if (owned && currentLockToken === token) {
    currentLockToken = null;
  }
}

async function withLock(fn) {
  if (!CLOUD) return fn();
  await init();
  const token = await acquireLock();
  currentLockToken = token;
  try {
    await loadCloud();
    const result = await fn();
    await flushCloud();
    return result;
  } finally {
    if (currentLockToken === token) currentLockToken = null;
    await releaseLock(token);
  }
}

function save() {
  if (CLOUD) {
    dirty = true;
    return;
  }
  saveLocal();
}

function flush() {
  if (CLOUD) return flushCloud();
  flushLocal();
  return undefined;
}

function flushSync() {
  if (CLOUD) return;
  flushLocal();
}

function hasChanges() {
  return dirty;
}

/* ------------------------------ файлы (Blob / FS) ------------------------- */

function localPath(pathname) {
  const full = path.resolve(DATA_DIR, pathname);
  const root = DATA_DIR.endsWith(path.sep) ? DATA_DIR : DATA_DIR + path.sep;
  if (!full.startsWith(root)) throw new Error('bad_storage_path');
  return full;
}

async function writeStoredFile(pathname, buffer) {
  if (CLOUD) {
    const { put } = require('@vercel/blob');
    return put(pathname, buffer, {
      access: 'private',
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: 'application/octet-stream',
      cacheControlMaxAge: 60,
    });
  }
  const full = localPath(pathname);
  await fs.promises.mkdir(path.dirname(full), { recursive: true });
  await fs.promises.writeFile(full, buffer);
  return { pathname };
}

async function readStoredFile(pathname) {
  const opened = await openStoredFile(pathname);
  if (!opened) return null;
  const chunks = [];
  for await (const chunk of opened.stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/**
 * Открывает файл как поток, чтобы не буферизовать большие вложения
 * (у Vercel Functions ограничение на размер тела ответа).
 */
async function openStoredFile(pathname) {
  if (CLOUD) {
    const { get } = require('@vercel/blob');
    try {
      const result = await get(pathname, { access: 'private', useCache: false });
      if (!result || result.statusCode !== 200 || !result.stream) return null;
      return {
        stream: Readable.fromWeb(result.stream),
        // Blob отдаёт поток без content-length, и SDK в этом случае пишет size: 0.
        // Ноль здесь означает «размер неизвестен», а не пустой файл.
        size: result.blob && result.blob.size > 0 ? result.blob.size : null,
      };
    } catch (err) {
      if (err && (err.name === 'BlobNotFoundError' || err.statusCode === 404)) return null;
      throw err;
    }
  }

  const full = localPath(pathname);
  try {
    const stat = await fs.promises.stat(full);
    if (!stat.isFile()) return null;
    return { stream: fs.createReadStream(full), size: stat.size };
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

/* -------------------------------- завершение ------------------------------ */

if (!CLOUD) {
  process.on('exit', flushSync);
  process.on('SIGINT', () => {
    flushSync();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    flushSync();
    process.exit(0);
  });
}

module.exports = {
  db,
  save,
  flush,
  flushSync,
  init,
  refresh,
  withLock,
  hasChanges,
  writeStoredFile,
  readStoredFile,
  openStoredFile,
  isCloud: CLOUD,
  DATA_DIR,
  FILES_DIR,
  AVATARS_DIR,
  DB_FILE,
  KEY_FILE,
};
