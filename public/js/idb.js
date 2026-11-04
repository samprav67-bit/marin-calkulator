'use strict';

/**
 * Крошечная обёртка над IndexedDB.
 * Здесь живёт приватный ключ устройства: он не покидает браузер.
 */

const DB_NAME = 'security-messenger';
const STORE = 'kv';
let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

function tx(mode, fn) {
  return openDb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE, mode);
        const store = transaction.objectStore(STORE);
        let result;
        try {
          result = fn(store);
        } catch (err) {
          reject(err);
          return;
        }
        transaction.oncomplete = () => resolve(result && result.result !== undefined ? result.result : result);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error);
      }),
  );
}

export function get(key) {
  return tx('readonly', (store) => store.get(key));
}

export function set(key, value) {
  return tx('readwrite', (store) => store.put(value, key));
}

export function remove(key) {
  return tx('readwrite', (store) => store.delete(key));
}

export async function clearAll() {
  await tx('readwrite', (store) => store.clear());
}
