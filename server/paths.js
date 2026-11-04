'use strict';

/**
 * Определение путей для обычного запуска, pkg и Node SEA (.exe).
 */

const path = require('path');

function isSea() {
  try {
    const sea = require('node:sea');
    return !!(sea && typeof sea.isSea === 'function' && sea.isSea());
  } catch {
    return false;
  }
}

const PACKAGED = !!process.pkg || isSea();
const EXEC_DIR = path.dirname(process.execPath);
const SOURCE_ROOT = path.join(__dirname, '..');

// Данные всегда рядом с исполняемым файлом в собранном виде.
const ROOT = PACKAGED ? EXEC_DIR : SOURCE_ROOT;

// Статика: pkg кладёт public/ внутрь snapshot, SEA и обычный запуск читают с диска.
let PUBLIC_DIR;
if (process.pkg) {
  PUBLIC_DIR = path.join(SOURCE_ROOT, 'public');
} else {
  PUBLIC_DIR = path.join(ROOT, 'public');
}

module.exports = { PACKAGED, ROOT, EXEC_DIR, SOURCE_ROOT, PUBLIC_DIR };
