'use strict';

import { getToken } from './api.js';

export const $ = (id) => document.getElementById(id);

export function icon(name, cls = 'icon') {
  return `<svg class="${cls}"><use href="#i-${name}"/></svg>`;
}

export function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function initials(name) {
  const clean = String(name || '?').trim();
  if (!clean) return '?';
  const parts = clean.split(/\s+/).slice(0, 2);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function hashString(value) {
  let hash = 2166136261;
  const text = String(value || '');
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash);
}

export function paintAvatar(el, user, { online = false, showPresence = false } = {}) {
  if (!el) return;
  el.style.background = '';
  el.style.backgroundImage = '';
  el.innerHTML = '';

  const hasImage = user && user.avatarUrl;
  if (hasImage) {
    const img = document.createElement('img');
    const token = getToken();
    img.src = token
      ? `${user.avatarUrl}${user.avatarUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`
      : user.avatarUrl;
    img.alt = '';
    img.style.width = '100%';
    img.style.height = '100%';
    img.style.objectFit = 'cover';
    img.style.borderRadius = '50%';
    img.style.display = 'block';
    el.appendChild(img);
    el.style.background = 'transparent';
  } else {
    const hue = hashString(user && (user.id || user.name)) % 360;
    el.style.background = `linear-gradient(135deg, hsl(${hue} 48% 42%), hsl(${(hue + 42) % 360} 56% 27%))`;
    el.innerHTML =
      `<span class="avatar-text">${escapeHtml(initials(user && user.name))}</span>`;
  }

  if (showPresence) {
    let dot = el.querySelector('.presence-dot');
    if (!dot) {
      dot = document.createElement('span');
      dot.className = 'presence-dot';
      el.appendChild(dot);
    }
    dot.classList.toggle('online', !!online);
  }
}

export function setPresenceDot(avatarEl, online) {
  if (!avatarEl) return;
  let dot = avatarEl.querySelector('.presence-dot');
  if (!dot) {
    dot = document.createElement('span');
    dot.className = 'presence-dot';
    avatarEl.appendChild(dot);
  }
  dot.classList.toggle('online', !!online);
}

export function formatPhone(phone) {
  if (!phone) return '';
  if (phone.startsWith('7') && phone.length === 11) {
    return `+7 ${phone.slice(1, 4)} ${phone.slice(4, 7)}-${phone.slice(7, 9)}-${phone.slice(9)}`;
  }
  return `+${phone}`;
}

export function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

export function formatChatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  if (sameDay) return formatTime(iso);
  const diff = (now - date) / 86400000;
  if (diff < 7) return date.toLocaleDateString('ru-RU', { weekday: 'short' });
  return date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
}

export function formatDay(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const now = new Date();
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (date.toDateString() === now.toDateString()) return 'Сегодня';
  if (date.toDateString() === yesterday.toDateString()) return 'Вчера';
  return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
}

export function dayKey(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

export function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} МБ`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} ГБ`;
}

export function formatDuration(seconds) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  return `${minutes}:${String(rest).padStart(2, '0')}`;
}

export function toast(text, kind = 'info', timeout = 3200) {
  const root = $('toasts');
  if (!root) return;
  const el = document.createElement('div');
  el.className = `toast ${kind === 'error' ? 'error' : ''}`;
  el.textContent = text;
  root.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity .18s ease, transform .18s ease';
    el.style.opacity = '0';
    el.style.transform = 'translateY(8px)';
    setTimeout(() => el.remove(), 200);
  }, timeout);
}

export function openModal({ title, body = '', actions = [], onMount, className = '' }) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal ${className}" role="dialog" aria-modal="true">
      <div class="modal-head">
        <div class="modal-title">${escapeHtml(title)}</div>
        <button class="icon-btn" data-close aria-label="Закрыть">${icon('x')}</button>
      </div>
      <div class="modal-body">${body}</div>
      <div class="modal-actions"></div>
    </div>
  `;

  const modal = backdrop.querySelector('.modal');
  const actionsRoot = backdrop.querySelector('.modal-actions');
  const bodyRoot = backdrop.querySelector('.modal-body');

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    backdrop.remove();
    document.removeEventListener('keydown', onKey);
  };

  const onKey = (event) => {
    if (event.key === 'Escape') close();
  };
  document.addEventListener('keydown', onKey);

  for (const action of actions) {
    const btn = document.createElement('button');
    btn.className = `btn ${action.variant === 'primary' ? 'btn-primary' : action.variant === 'danger' ? 'btn-danger' : 'btn-ghost'}`;
    btn.type = 'button';
    btn.textContent = action.label;
    if (action.disabled) btn.disabled = true;
    btn.addEventListener('click', () => action.onClick ? action.onClick(close, btn) : close());
    actionsRoot.appendChild(btn);
  }
  if (!actions.length) actionsRoot.remove();

  backdrop.addEventListener('mousedown', (event) => {
    if (event.target === backdrop) close();
  });
  backdrop.querySelector('[data-close]').addEventListener('click', close);

  document.getElementById('modal-root').appendChild(backdrop);
  if (onMount) onMount({ root: modal, body: bodyRoot, close });
  const focusTarget = modal.querySelector('input, textarea');
  if (focusTarget) setTimeout(() => focusTarget.focus(), 30);

  return close;
}
