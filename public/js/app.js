'use strict';

import { api, setToken } from './api.js';
import * as crypto from './crypto.js';
import * as ui from './ui.js';
import { CallManager } from './calls.js';

const { $, icon } = ui;

/* ================================ Состояние ============================ */

const state = {
  me: null,
  identity: null,
  chats: [],
  chatMap: new Map(),
  activeId: null,
  messages: [],
  decrypted: new Map(),
  online: new Set(),
  hasMore: false,
  loadingOlder: false,
  sending: false,
  cloud: false,
  search: '',
  events: null,
  eventCursor: null,
  everReady: false,
  reconnectTimer: null,
  pollBusy: false,
  typingSentAt: 0,
  typingHideTimer: null,
  audioCache: new Map(),
  voice: { id: null, btn: null, wave: null, timeEl: null, duration: 0 },
};

const audio = new Audio();
audio.preload = 'auto';

let authIdentifier = '';
let authKind = 'phone';
let authChallenge = '';
let pendingOpenChat = null;
let appName = 'Security';
let betaMode = false;

const AUTH_ERRORS = {
  bad_phone: 'Введите корректный номер телефона.',
  bad_identifier: 'Введите корректный номер телефона или адрес Gmail.',
  bad_email: 'Введите корректный адрес Gmail.',
  bad_code: 'Код должен состоять из 6 цифр.',
  code_not_requested: 'Сначала запросите код.',
  code_expired: 'Код истёк. Запросите новый.',
  wrong_code: 'Неверный код. Попробуйте ещё раз.',
  too_many_attempts: 'Слишком много попыток. Запросите новый код.',
  phone_beta_only: 'Вход по телефону доступен только в бета-режиме. Используйте Gmail.',
  email_not_configured: 'Gmail не настроен. Укажите SMTP_USER и SMTP_PASS (пароль приложения) в security.config.json.',
  bad_access_code: 'Код доступа должен состоять из 8 символов.',
  access_expired: 'Время ввода кода доступа истекло. Войдите заново.',
  too_many_access_attempts: 'Слишком много попыток ввода кода доступа. Войдите заново.',
  wrong_access_code: 'Неверный код доступа. Проверьте код в профиле → «Безопасность».',
  network: 'Нет связи с сервером. Проверьте подключение.',
};

function humanError(err) {
  return AUTH_ERRORS[err && err.message] || 'Что-то пошло не так. Попробуйте ещё раз.';
}

/* ================================ Бренд =============================== */

function applyBranding(name) {
  appName = name || 'Security';
  document.title = `${appName} — защищённый мессенджер`;
  for (const el of document.querySelectorAll('.brand-name')) {
    el.textContent = appName;
  }
}

function applyAuthMode(mode, beta) {
  const label = document.querySelector('label[for="phone-input"]');
  const input = $('phone-input');
  const hint = document.querySelector('#phone-form .hint');
  if (!label || !input || !hint) return;
  if (mode === 'email' && !beta) {
    label.textContent = 'Gmail';
    input.placeholder = 'name@gmail.com';
    hint.textContent = 'Отправим 6-значный код письмом на Gmail.';
  } else if (mode === 'sms') {
    label.textContent = 'Номер телефона';
    input.placeholder = '+7 900 000-00-00';
    hint.textContent = 'Отправим 6-значный код по SMS на телефон.';
  } else {
    label.textContent = 'Телефон или Gmail';
    input.placeholder = '+7 900 000-00-00 или name@gmail.com';
    hint.textContent = beta
      ? 'Бета-режим: 6-значный код появится прямо на экране.'
      : 'Отправим 6-значный код по SMS или на Gmail.';
  }
}

/* ================================ Помощники =========================== */

function contactLabel(user) {
  if (!user) return '';
  if (user.phone) return ui.formatPhone(user.phone);
  if (user.email) return user.email;
  return '';
}

function peerName(peer) {
  if (!peer) return 'Без имени';
  return peer.name || contactLabel(peer) || 'Без имени';
}

function chatOfActive() {
  return state.chatMap.get(state.activeId) || null;
}

function isPeerOnline(peer) {
  return !!(peer && (state.online.has(peer.id) || peer.online));
}

function scrollToBottom() {
  const el = $('messages');
  requestAnimationFrame(() => {
    el.scrollTop = el.scrollHeight;
  });
}

function nearBottom() {
  const el = $('messages');
  return el.scrollHeight - el.scrollTop - el.clientHeight < 140;
}

function updateSendVisibility() {
  const input = $('msg-input');
  const hasText = input.value.trim().length > 0;
  $('btn-send').hidden = !hasText;
  $('btn-voice').hidden = hasText;
}

function autoGrow() {
  const input = $('msg-input');
  input.style.height = 'auto';
  input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
}

/* =============================== Авторизация ========================== */

function setAuthError(message) {
  const el = $('auth-error');
  el.textContent = message || '';
  el.hidden = !message;
}

function resetAuthForms() {
  authChallenge = '';
  $('phone-form').hidden = false;
  $('code-form').hidden = true;
  $('access-form').hidden = true;
  $('dev-code').hidden = true;
  $('dev-code').className = 'dev-code';
  $('dev-code').innerHTML = '';
  $('auth-error').hidden = true;
  $('phone-input').value = '';
  $('access-input').value = '';
  for (const input of $('code-inputs').querySelectorAll('input')) input.value = '';
}

function focusCode(index = 0) {
  const inputs = $('code-inputs').querySelectorAll('input');
  if (inputs[index]) inputs[index].focus();
}

function normalizeAccessInput(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
}

function formatAccessCode(code) {
  const raw = normalizeAccessInput(code);
  return raw.length === 8 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* используем запасной способ */
  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  } catch {
    return false;
  }
}

function showAccessCodeModal(code, isNew) {
  const formatted = formatAccessCode(code);
  ui.openModal({
    title: isNew ? 'Код доступа создан' : 'Код доступа',
    body: `
      <p>${isNew
        ? 'Аккаунт создан. Для этого аккаунта создан постоянный код доступа.'
        : 'Постоянный код доступа для этого аккаунта.'}</p>
      <p>Он понадобится при следующем входе на этот номер или Gmail. Сохраните его в надёжном месте.</p>
      <div class="access-code-box"><span>${ui.escapeHtml(formatted)}</span></div>
      <p class="hint">Код хранится в зашифрованной базе. Посмотреть или сменить его можно в профиле → «Безопасность».</p>
    `,
    actions: [
      {
        label: 'Скопировать',
        variant: 'ghost',
        onClick: async () => {
          const ok = await copyText(formatted);
          ui.toast(ok ? 'Код скопирован' : 'Не удалось скопировать код', ok ? 'info' : 'error');
        },
      },
      { label: 'Понятно', variant: 'primary' },
    ],
  });
}

async function finishLogin(res) {
  setToken(res.token);
  state.me = res.user;
  await enterApp();
  if (res.accessCode) {
    const code = res.accessCode;
    setTimeout(() => showAccessCodeModal(code, true), 300);
  }
}

function renderLoginCodeBox(res) {
  const dev = $('dev-code');
  dev.hidden = false;
  if (res.betaCode) {
    dev.className = 'dev-code beta-code';
    dev.innerHTML = `
      <span class="beta-label">Бета-режим · код входа</span>
      <b>${ui.escapeHtml(res.betaCode)}</b>
      <span class="beta-hint">Введите эти 6 цифр ниже. Код действует 5 минут.</span>
    `;
    return 'beta';
  }
  dev.className = 'dev-code';
  const where = ui.escapeHtml(res.formatted || res.identifier);
  const isEmail = (res.kind || authKind) === 'email';
  dev.innerHTML = isEmail
    ? `Код отправлен письмом на ${where}. Проверьте Gmail и папку «Спам».`
    : `Код отправлен по SMS на ${where}. Введите 6 цифр из SMS.`;
  return isEmail ? 'email' : 'sms';
}

function bindAuth() {
  $('phone-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAuthError('');
    const button = $('btn-phone-submit');
    button.disabled = true;
    try {
      const res = await api.post('/auth/start', { identifier: $('phone-input').value.trim() });
      authIdentifier = res.identifier;
      authKind = res.kind || 'phone';
      authChallenge = '';
      $('auth-phone').textContent = res.formatted || res.identifier;
      $('phone-form').hidden = true;
      $('code-form').hidden = false;
      $('access-form').hidden = true;
      renderLoginCodeBox(res);
      for (const input of $('code-inputs').querySelectorAll('input')) input.value = '';
      setTimeout(() => focusCode(0), 80);
    } catch (err) {
      setAuthError(humanError(err));
    } finally {
      button.disabled = false;
    }
  });

  $('code-inputs').addEventListener('input', (event) => {
    const input = event.target;
    input.value = input.value.replace(/\D/g, '').slice(0, 1);
    input.classList.toggle('filled', !!input.value);
    if (input.value) {
      const inputs = [...$('code-inputs').querySelectorAll('input')];
      const index = inputs.indexOf(input);
      if (index < inputs.length - 1) inputs[index + 1].focus();
    }
  });

  $('code-inputs').addEventListener('keydown', (event) => {
    const inputs = [...$('code-inputs').querySelectorAll('input')];
    const index = inputs.indexOf(event.target);
    if (event.key === 'Backspace' && !event.target.value && index > 0) {
      inputs[index - 1].focus();
      inputs[index - 1].value = '';
      inputs[index - 1].classList.remove('filled');
      event.preventDefault();
    }
    if (event.key === 'ArrowLeft' && index > 0) inputs[index - 1].focus();
    if (event.key === 'ArrowRight' && index < inputs.length - 1) inputs[index + 1].focus();
  });

  $('code-inputs').addEventListener('paste', (event) => {
    const text = (event.clipboardData || window.clipboardData).getData('text') || '';
    const digits = text.replace(/\D/g, '').slice(0, 6);
    if (!digits) return;
    event.preventDefault();
    const inputs = [...$('code-inputs').querySelectorAll('input')];
    digits.split('').forEach((digit, i) => {
      inputs[i].value = digit;
      inputs[i].classList.add('filled');
    });
    focusCode(Math.min(digits.length, 5));
    if (digits.length === 6) $('code-form').requestSubmit();
  });

  $('code-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAuthError('');
    const inputs = [...$('code-inputs').querySelectorAll('input')];
    const code = inputs.map((input) => input.value).join('');
    if (code.length !== 6) {
      setAuthError('Введите все 6 цифр кода.');
      return;
    }
    const button = $('btn-code-submit');
    button.disabled = true;
    try {
      const res = await api.post('/auth/verify', { identifier: authIdentifier, code });
      if (res.accessRequired) {
        authChallenge = res.challenge;
        $('code-form').hidden = true;
        $('access-form').hidden = false;
        $('access-phone').textContent = res.formatted || authIdentifier;
        $('access-input').value = '';
        setAuthError('');
        setTimeout(() => $('access-input').focus(), 80);
        ui.toast('Введите постоянный код доступа');
        return;
      }
      await finishLogin(res);
    } catch (err) {
      setAuthError(humanError(err));
      inputs.forEach((input) => {
        input.value = '';
        input.classList.remove('filled');
      });
      focusCode(0);
    } finally {
      button.disabled = false;
    }
  });

  $('btn-change-phone').addEventListener('click', () => {
    resetAuthForms();
    $('phone-input').focus();
  });

  $('btn-resend').addEventListener('click', async () => {
    setAuthError('');
    try {
      const res = await api.post('/auth/start', { identifier: authIdentifier });
      const channel = renderLoginCodeBox(res);
      if (channel === 'beta') {
        ui.toast(res.reused ? 'Код всё ещё действует' : 'Новый код показан на экране');
      } else {
        ui.toast(res.reused ? 'Код уже отправлен, подождите немного' : 'Код отправлен повторно');
      }
    } catch (err) {
      setAuthError(humanError(err));
    }
  });

  $('access-input').addEventListener('input', () => {
    const input = $('access-input');
    input.value = formatAccessCode(input.value);
  });

  $('access-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    setAuthError('');
    const raw = normalizeAccessInput($('access-input').value);
    if (raw.length !== 8) {
      setAuthError('Код доступа должен состоять из 8 символов.');
      return;
    }
    if (!authChallenge) {
      setAuthError('Сессия входа истекла. Запросите код заново.');
      resetAuthForms();
      return;
    }
    const button = $('btn-access-submit');
    button.disabled = true;
    try {
      const res = await api.post('/auth/access', { challenge: authChallenge, code: raw });
      await finishLogin(res);
    } catch (err) {
      setAuthError(humanError(err));
      const message = err && err.message;
      if (message === 'access_expired' || message === 'too_many_access_attempts') {
        setTimeout(() => {
          resetAuthForms();
          $('phone-input').focus();
        }, 1400);
      } else {
        $('access-input').value = '';
        $('access-input').focus();
      }
    } finally {
      button.disabled = false;
    }
  });

  $('btn-access-back').addEventListener('click', () => {
    resetAuthForms();
    $('phone-input').focus();
  });
}

/* ============================== Вход в приложение ===================== */

async function enterApp() {
  $('auth').hidden = true;
  $('app').hidden = false;

  state.identity = await crypto.ensureIdentity(state.me.id);
  if (state.me.publicKey !== state.identity.publicKey) {
    const res = await api.put('/me/keys', { publicKey: state.identity.publicKey });
    state.me = res.user;
  }

  ui.paintAvatar($('me-avatar'), state.me);
  $('me-name').textContent = state.me.name;
  $('me-phone').textContent = contactLabel(state.me);

  connectEvents();
  await loadChats();

  if (pendingOpenChat) {
    openChat(pendingOpenChat);
    pendingOpenChat = null;
  }
}

/* ================================ События ============================= */

function connectEvents() {
  if (state.events) {
    try {
      state.events.close();
    } catch {
      /* уже закрыт */
    }
    state.events = null;
  }
  clearTimeout(state.reconnectTimer);

  const poll = {
    closed: false,
    close() {
      this.closed = true;
      clearTimeout(state.reconnectTimer);
      if (state.events === this) state.events = null;
    },
  };
  state.events = poll;
  state.eventCursor = null;
  state.everReady = false;
  state.pollBusy = false;

  const schedule = (delay) => {
    if (poll.closed || state.events !== poll) return;
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = setTimeout(tick, delay);
  };

  const tick = async () => {
    if (poll.closed || state.events !== poll || !state.me) return;
    if (state.pollBusy) {
      schedule(800);
      return;
    }
    state.pollBusy = true;
    try {
      const path = state.eventCursor == null
        ? '/events/poll?init=1'
        : `/events/poll?since=${state.eventCursor}`;
      const res = await api.get(path);
      if (poll.closed || state.events !== poll) return;

      state.eventCursor = res.cursor;
      state.online = new Set(res.online || []);
      renderChatList();
      if (state.activeId) renderHeader();

      // Первый ответ: забираем актуальный список чатов и историю.
      if (!state.everReady) {
        state.everReady = true;
        await loadChats();
        if (state.activeId) await loadMessages(state.activeId);
      }

      for (const item of res.events || []) {
        if (poll.closed) break;
        await onRealtimeEvent(item.type, item.data);
      }

      // Журнал ограничен, поэтому при переполнении дочитываем состояние целиком.
      if ((res.events || []).length >= 100) await syncFromServer();
    } catch {
      /* сеть недоступна — следующий тик повторит */
    } finally {
      state.pollBusy = false;
      if (poll.closed || state.events !== poll) return;
      let delay = document.visibilityState === 'hidden' ? 9000 : 3500;
      if (calls.busy) delay = 1200;
      schedule(delay);
    }
  };

  tick();
}

async function onRealtimeEvent(type, data) {
  if (!data) return;

  if (type === 'presence') {
    if (data.online) state.online.add(data.userId);
    else state.online.delete(data.userId);
    renderChatList();
    if (state.activeId) renderHeader();
    return;
  }

  if (type === 'message') {
    if (data.message) onIncomingMessage(data.message);
    return;
  }

  if (type === 'read') {
    const chat = state.chatMap.get(data.chatId);
    if (!chat) return;
    chat.peerLastRead = data.upTo;
    if (state.activeId === data.chatId) refreshTicks();
    return;
  }

  if (type === 'typing') {
    if (data.chatId !== state.activeId) return;
    const typing = $('typing');
    typing.hidden = false;
    clearTimeout(state.typingHideTimer);
    state.typingHideTimer = setTimeout(() => {
      typing.hidden = true;
    }, 3500);
    const el = $('messages');
    if (nearBottom()) el.scrollTop = el.scrollHeight;
    return;
  }

  if (type === 'call') {
    if (data.call) await calls.handleSignal(data);
    return;
  }

  if (type === 'keychange') {
    const peerId = data.userId;
    const known = state.chats.find((chat) => chat.peer && chat.peer.id === peerId);
    const hadKey = !!(known && known.peer && known.peer.publicKey);
    await loadChats();
    if (hadKey) {
      ui.toast('Собеседник обновил ключ шифрования. Сверьте код безопасности.', 'error', 6000);
    } else {
      ui.toast('Собеседник подключил шифрование', 'info');
    }
    return;
  }

  if (type === 'profile') {
    if (!data.user) return;
    for (const chat of state.chats) {
      if (chat.peer && chat.peer.id === data.user.id) {
        chat.peer = { ...chat.peer, ...data.user, online: chat.peer.online };
      }
    }
    renderChatList();
    if (state.activeId) renderHeader();
  }
}

/* ================================ Чаты ================================ */

async function loadChats() {
  const res = await api.get('/chats');  state.chats = res.chats || [];
  state.chatMap = new Map(state.chats.map((chat) => [chat.id, chat]));
  for (const chat of state.chats) {
    if (chat.peer && chat.peer.online) state.online.add(chat.peer.id);
  }
  renderChatList();
  if (state.activeId && state.chatMap.has(state.activeId)) {
    renderHeader();
    updateComposerState();
  }
}

async function syncFromServer() {
  try {
    await loadChats();
    const chatId = state.activeId;
    if (!chatId) return;
    const res = await api.get(`/chats/${chatId}/messages?limit=30`);
    if (state.activeId !== chatId) return;
    let added = false;
    for (const message of res.messages || []) {
      const known = state.messages.some(
        (item) => item.id === message.id || (message.clientId && item.clientId === message.clientId),
      );
      if (!known) {
        appendMessage(message);
        added = true;
      }
    }
    if (added) {
      const last = res.messages[res.messages.length - 1];
      const chat = state.chatMap.get(chatId);
      if (chat && last) {
        chat.lastMessage = last;
        chat.lastMessageAt = last.createdAt;
      }
      scrollToBottom();
      await markRead(chatId);
    }
  } catch {
    /* повторим на следующем тике */
  }
}

function renderChatList() {
  const list = $('chat-list');
  list.innerHTML = '';
  const query = state.search.trim().toLowerCase();
  const digits = query.replace(/\D/g, '');

  const chats = state.chats.filter((chat) => {
    if (!query) return true;
    const name = (chat.peer && chat.peer.name ? chat.peer.name : '').toLowerCase();
    const phone = chat.peer && chat.peer.phone ? chat.peer.phone : '';
    const email = chat.peer && chat.peer.email ? chat.peer.email.toLowerCase() : '';
    return name.includes(query) || email.includes(query) || (digits && phone.includes(digits));
  });

  if (!chats.length) {
    const empty = document.createElement('div');
    empty.className = 'chat-empty';
    empty.innerHTML = query
      ? 'Ничего не найдено.<br>Попробуйте другой запрос.'
      : 'Пока нет диалогов.<br>Начните первый разговор — <b>+</b> вверху.';
    list.appendChild(empty);
    return;
  }

  for (const chat of chats) {
    list.appendChild(renderChatItem(chat));
  }
}

function renderChatItem(chat) {
  const item = document.createElement('button');
  item.type = 'button';
  item.dataset.id = chat.id;
  item.className =
    'chat-item' +
    (chat.id === state.activeId ? ' active' : '') +
    (chat.unread > 0 ? ' unread' : '');

  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  ui.paintAvatar(avatar, chat.peer, {
    showPresence: true,
    online: isPeerOnline(chat.peer),
  });
  item.appendChild(avatar);

  const body = document.createElement('div');
  body.className = 'chat-body';

  const line = document.createElement('div');
  line.className = 'chat-line';

  const name = document.createElement('div');
  name.className = 'chat-name';
  name.textContent = peerName(chat.peer);
  line.appendChild(name);

  const last = chat.lastMessage;
  if (last) {
    const time = document.createElement('div');
    time.className = 'chat-time';
    time.textContent = ui.formatChatTime(last.createdAt);
    line.appendChild(time);
  }

  if (chat.unread > 0) {
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = chat.unread > 99 ? '99+' : String(chat.unread);
    line.appendChild(badge);
  }

  body.appendChild(line);

  const preview = document.createElement('div');
  preview.className = 'chat-preview';
  const text = document.createElement('span');
  text.textContent = last ? '···' : 'Нет сообщений';
  preview.appendChild(text);
  body.appendChild(preview);

  item.appendChild(body);

  if (last) {
    const prefix = last.senderId === state.me.id ? 'Вы: ' : '';
    describeMessage(last).then((description) => {
      if (item.isConnected) text.textContent = prefix + description;
    });
  }

  return item;
}

async function describeMessage(message) {
  if (message.kind === 'voice') return 'Голосовое сообщение';
  if (message.kind === 'file') {
    try {
      const data = await decryptMessage(message);
      return `Файл: ${(data.file && data.file.name) || 'без имени'}`;
    } catch {
      return 'Файл';
    }
  }
  try {
    const data = await decryptMessage(message);
    const text = String((data && data.text) || '').replace(/\s+/g, ' ').trim();
    return text.slice(0, 90) || 'Сообщение';
  } catch {
    return 'Не удалось расшифровать';
  }
}

function onIncomingMessage(message) {
  const chat = state.chatMap.get(message.chatId);
  if (!chat) {
    loadChats().then(() => {
      if (state.activeId === message.chatId) onIncomingMessage(message);
    });
    return;
  }

  chat.lastMessage = message;
  chat.lastMessageAt = message.createdAt;

  const own = message.senderId === state.me.id;

  if (state.activeId === message.chatId) {
    if (own) {
      upsertMessage(message);
    } else {
      appendMessage(message);
      scrollToBottom();
      markRead(message.chatId);
    }
  } else if (!own) {
    chat.unread = (chat.unread || 0) + 1;
  }

  renderChatList();
}

async function openChat(chatId) {
  const chat = state.chatMap.get(chatId);
  if (!chat) return;

  stopVoice();
  clearTimeout(state.typingHideTimer);
  $('typing').hidden = true;

  state.activeId = chatId;
  state.messages = [];
  state.hasMore = false;
  chat.unread = 0;

  $('empty-state').hidden = true;
  $('chat-view').hidden = false;
  $('app').classList.add('chat-open');

  renderChatList();
  renderHeader();
  updateComposerState();
  $('messages').innerHTML = '';
  $('msg-input').value = '';
  autoGrow();
  updateSendVisibility();

  await loadMessages(chatId);
  await markRead(chatId);
  $('msg-input').focus();
}

async function loadMessages(chatId) {
  const res = await api.get(`/chats/${chatId}/messages?limit=60`);
  if (state.activeId !== chatId) return;
  state.messages = res.messages || [];
  state.hasMore = !!res.hasMore;
  renderMessages();
  scrollToBottom();
  setTimeout(scrollToBottom, 180);
  setTimeout(scrollToBottom, 520);
}

function renderMessages() {
  const container = $('messages');
  container.innerHTML = '';

  if (state.hasMore) {
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'load-more';
    more.textContent = 'Загрузить историю';
    more.addEventListener('click', loadOlder);
    container.appendChild(more);
  }

  let lastDay = null;
  for (const message of state.messages) {
    const day = ui.dayKey(message.createdAt);
    if (day !== lastDay) {
      const separator = document.createElement('div');
      separator.className = 'day-sep';
      separator.textContent = ui.formatDay(message.createdAt);
      container.appendChild(separator);
      lastDay = day;
    }
    container.appendChild(createRow(message));
  }
}

async function loadOlder() {
  const chatId = state.activeId;
  if (!chatId || state.loadingOlder || !state.messages.length) return;
  state.loadingOlder = true;
  const anchorId = state.messages[0].id;
  try {
    const before = encodeURIComponent(state.messages[0].createdAt);
    const res = await api.get(`/chats/${chatId}/messages?limit=60&before=${before}`);
    if (state.activeId !== chatId) return;
    state.messages = [...(res.messages || []), ...state.messages];
    state.hasMore = !!res.hasMore;
    renderMessages();
    keepAnchor(anchorId);
    setTimeout(() => keepAnchor(anchorId), 220);
  } finally {
    state.loadingOlder = false;
  }
}

function keepAnchor(anchorId) {
  const container = $('messages');
  const row = container.querySelector(`.msg-row[data-id="${anchorId}"]`);
  if (!row) return;
  const containerRect = container.getBoundingClientRect();
  const rowRect = row.getBoundingClientRect();
  container.scrollTop += rowRect.top - containerRect.top - 14;
}

/* ============================== Сообщения ============================= */

function decryptCacheKey(message) {
  return message.id;
}

async function decryptMessage(message) {
  const key = decryptCacheKey(message);
  if (state.decrypted.has(key)) return state.decrypted.get(key);
  const payload = message.senderId === state.me.id
    ? message.payload && message.payload.forSelf
    : message.payload && message.payload.forPeer;
  if (!payload) throw new Error('no_payload');
  const data = await crypto.decryptWith(state.identity, payload);
  state.decrypted.set(key, data);
  return data;
}

function createRow(message) {
  const row = document.createElement('div');
  row.className = `msg-row ${message.senderId === state.me.id ? 'own' : 'peer'}`;
  row.dataset.id = message.id;
  row.innerHTML =
    '<div class="bubble"><div class="msg-body"></div>' +
    '<div class="msg-meta"><span class="msg-time"></span><span class="msg-ticks"></span></div></div>';
  fillRow(row, message);
  return row;
}

async function fillRow(row, message) {
  const body = row.querySelector('.msg-body');
  const time = row.querySelector('.msg-time');
  const ticks = row.querySelector('.msg-ticks');
  if (!body) return;

  time.textContent = ui.formatTime(message.createdAt);
  updateTicks(ticks, message);

  if (message.__failed) {
    body.innerHTML = `<span class="msg-error">${icon('lock')} Не отправлено</span>`;
    return;
  }

  body.textContent = '···';
  try {
    const data = await decryptMessage(message);
    body.textContent = '';
    if (message.kind === 'text') renderText(body, data.text);
    else if (message.kind === 'file') renderFile(body, message, data.file);
    else if (message.kind === 'voice') renderVoice(body, message, data.voice);
    else body.textContent = 'Сообщение';
  } catch {
    body.innerHTML = `<span class="msg-error">${icon('lock')} Не удалось расшифровать</span>`;
  }
}

function renderText(container, text) {
  container.classList.add('msg-text');
  const value = String(text == null ? '' : text);
  const parts = value.split(/(https?:\/\/[^\s]+)/g);
  for (const part of parts) {
    if (!part) continue;
    if (/^https?:\/\//.test(part)) {
      const link = document.createElement('a');
      link.href = part;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = part;
      container.appendChild(link);
    } else {
      container.appendChild(document.createTextNode(part));
    }
  }
}

function renderFile(container, message, file) {
  if (!file) {
    container.textContent = 'Файл';
    return;
  }
  const card = document.createElement('div');
  card.className = 'file-card';
  card.innerHTML =
    `<div class="file-ico">${icon('file')}</div>` +
    '<div class="file-info"><div class="file-name"></div><div class="file-size"></div></div>' +
    `<button class="file-dl" type="button" title="Скачать">${icon('download')}</button>`;

  card.querySelector('.file-name').textContent = file.name || 'Файл';
  card.querySelector('.file-size').textContent = ui.formatBytes(file.size);

  const button = card.querySelector('.file-dl');
  button.addEventListener('click', () => downloadFile(file, button));

  container.appendChild(card);
}

async function downloadFile(file, button) {
  button.disabled = true;
  try {
    const encrypted = await api.buffer(`/files/${file.id}`);
    const plain = await crypto.decryptBytes(file.key, file.iv, encrypted);
    const blob = new Blob([plain], { type: file.mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = file.name || 'file';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch {
    ui.toast('Не удалось скачать файл', 'error');
  } finally {
    button.disabled = false;
  }
}

function waveHeights(seed, count = 34) {
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const bars = [];
  for (let i = 0; i < count; i += 1) {
    hash = (Math.imul(hash, 1103515245) + 12345) & 0x7fffffff;
    bars.push(4 + (hash % 17));
  }
  return bars;
}

function renderVoice(container, message, voice) {
  if (!voice) {
    container.textContent = 'Голосовое сообщение';
    return;
  }

  const wrap = document.createElement('div');
  wrap.className = 'voice';

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'voice-play';
  button.innerHTML = icon('play');

  const info = document.createElement('div');
  info.className = 'voice-body';

  const wave = document.createElement('div');
  wave.className = 'wave';
  for (const height of waveHeights(message.id)) {
    const bar = document.createElement('i');
    bar.style.height = `${height}px`;
    wave.appendChild(bar);
  }

  const time = document.createElement('div');
  time.className = 'voice-time';
  time.textContent = ui.formatDuration(voice.duration || 0);

  info.append(wave, time);
  wrap.append(button, info);

  button.addEventListener('click', () => toggleVoice(message, voice, button, wave, time));
  wave.addEventListener('click', (event) => {
    if (state.voice.id !== message.id) return;
    if (!Number.isFinite(audio.duration) || audio.duration <= 0) return;
    const rect = wave.getBoundingClientRect();
    const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
    audio.currentTime = audio.duration * ratio;
  });

  container.appendChild(wrap);
}

async function getAudioUrl(message, voice) {
  const cached = state.audioCache.get(message.id);
  if (cached) return cached;
  const encrypted = await api.buffer(`/files/${voice.id}`);
  const plain = await crypto.decryptBytes(voice.key, voice.iv, encrypted);
  const blob = new Blob([plain], { type: voice.mime || 'audio/webm' });
  const url = URL.createObjectURL(blob);
  state.audioCache.set(message.id, url);
  return url;
}

async function toggleVoice(message, voice, button, wave, timeEl) {
  if (state.voice.id === message.id && !audio.paused) {
    audio.pause();
    return;
  }
  if (state.voice.id === message.id && audio.src) {
    audio.play().catch(() => {});
    return;
  }

  stopVoice();
  button.disabled = true;
  try {
    const url = await getAudioUrl(message, voice);
    state.voice = { id: message.id, btn: button, wave, timeEl, duration: voice.duration || 0 };
    audio.src = url;
    await audio.play();
  } catch {
    ui.toast('Не удалось воспроизвести запись', 'error');
  } finally {
    button.disabled = false;
  }
}

function stopVoice() {
  try {
    audio.pause();
    audio.removeAttribute('src');
    audio.load();
  } catch {
    /* игнорируем */
  }
  if (state.voice.wave) {
    for (const bar of state.voice.wave.children) bar.classList.remove('on');
  }
  state.voice = { id: null, btn: null, wave: null, timeEl: null, duration: 0 };
}

audio.addEventListener('play', () => {
  if (state.voice.btn) state.voice.btn.innerHTML = icon('pause');
});
audio.addEventListener('pause', () => {
  if (state.voice.btn) state.voice.btn.innerHTML = icon('play');
});
audio.addEventListener('ended', () => {
  if (state.voice.wave) {
    for (const bar of state.voice.wave.children) bar.classList.remove('on');
  }
  if (state.voice.timeEl) {
    state.voice.timeEl.textContent = ui.formatDuration(state.voice.duration);
  }
  if (state.voice.btn) state.voice.btn.innerHTML = icon('play');
});
audio.addEventListener('timeupdate', () => {
  const current = state.voice;
  if (!current.wave) return;
  const duration = Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration : current.duration || 1;
  const ratio = Math.min(1, audio.currentTime / duration);
  const bars = current.wave.children;
  const active = Math.round(bars.length * ratio);
  for (let i = 0; i < bars.length; i += 1) {
    bars[i].classList.toggle('on', i < active);
  }
  if (current.timeEl) current.timeEl.textContent = ui.formatDuration(audio.currentTime);
});

/* ============================== Метрики чата ========================== */

function updateTicks(element, message) {
  if (!element) return;
  if (message.senderId !== state.me.id) {
    element.innerHTML = '';
    return;
  }
  const chat = state.chatMap.get(message.chatId);
  const read = !!(chat && chat.peerLastRead && message.createdAt <= chat.peerLastRead);
  element.innerHTML = read
    ? `<span class="read">${icon('check-double')}</span>`
    : icon('check');
  element.title = read ? 'Прочитано' : message.__failed ? 'Не отправлено' : 'Отправлено';
}

function refreshTicks() {
  for (const row of $('messages').querySelectorAll('.msg-row.own')) {
    const message = state.messages.find((item) => item.id === row.dataset.id);
    if (message) updateTicks(row.querySelector('.msg-ticks'), message);
  }
}

function appendMessage(message) {
  if (message.chatId !== state.activeId) return;
  if (state.messages.some((item) => item.id === message.id)) return;

  const container = $('messages');
  const last = state.messages[state.messages.length - 1];
  if (!last || ui.dayKey(last.createdAt) !== ui.dayKey(message.createdAt)) {
    const separator = document.createElement('div');
    separator.className = 'day-sep';
    separator.textContent = ui.formatDay(message.createdAt);
    container.appendChild(separator);
  }
  state.messages.push(message);
  container.appendChild(createRow(message));
}

function upsertMessage(message) {
  const index = state.messages.findIndex(
    (item) =>
      item.id === message.id ||
      (message.clientId && item.clientId && item.clientId === message.clientId),
  );

  if (index === -1) {
    if (message.chatId === state.activeId) {
      appendMessage(message);
      scrollToBottom();
    }
    return;
  }

  const previous = state.messages[index];
  state.messages[index] = message;
  if (state.decrypted.has(previous.id) && previous.id !== message.id) {
    state.decrypted.set(message.id, state.decrypted.get(previous.id));
  }

  const row = $('messages').querySelector(`.msg-row[data-id="${previous.id}"]`);
  if (row) {
    row.dataset.id = message.id;
    fillRow(row, message);
  }
}

/* =============================== Отправка ============================= */

function updateComposerState() {
  const chat = chatOfActive();
  const ready = !!(chat && chat.peer && chat.peer.publicKey);
  $('msg-input').disabled = !ready;
  $('btn-attach').disabled = !ready;
  $('btn-voice').disabled = !ready;
  $('msg-input').placeholder = ready
    ? 'Написать сообщение…'
    : 'У собеседника пока нет ключа шифрования';
}

async function sendMessage(chat, kind, body, extra = {}) {
  const payload = {
    v: 1,
    forPeer: await crypto.encryptFor(chat.peer.publicKey, body),
    forSelf: await crypto.encryptFor(state.identity.publicKey, body),
  };

  const clientId = crypto.randomId();
  const optimistic = {
    id: `tmp_${clientId}`,
    chatId: chat.id,
    senderId: state.me.id,
    kind,
    fileId: extra.fileId || null,
    payload,
    clientId,
    createdAt: new Date().toISOString(),
    __pending: true,
  };

  state.decrypted.set(optimistic.id, body);

  if (chat.id === state.activeId) {
    appendMessage(optimistic);
    scrollToBottom();
  }

  try {
    const res = await api.post(`/chats/${chat.id}/messages`, {
      kind,
      payload,
      fileId: extra.fileId || null,
      clientId,
    });
    upsertMessage(res.message);
    if (res.chat) {
      const current = state.chatMap.get(chat.id);
      if (current) {
        current.lastMessage = res.chat.lastMessage;
        current.lastMessageAt = res.chat.lastMessageAt;
        current.peerLastRead = res.chat.peerLastRead;
      }
      renderChatList();
    }
  } catch {
    optimistic.__failed = true;
    optimistic.__pending = false;
    state.decrypted.delete(optimistic.id);
    const row = $('messages').querySelector(`.msg-row[data-id="${optimistic.id}"]`);
    if (row) fillRow(row, optimistic);
    ui.toast('Сообщение не отправлено', 'error');
  }
}

async function sendText() {
  const chat = chatOfActive();
  const input = $('msg-input');
  const text = input.value.trim();
  if (!chat || !text || state.sending) return;
  if (!chat.peer || !chat.peer.publicKey) {
    ui.toast('У собеседника нет ключа шифрования', 'error');
    return;
  }

  state.sending = true;
  input.value = '';
  autoGrow();
  updateSendVisibility();
  try {
    await sendMessage(chat, 'text', { text });
  } finally {
    state.sending = false;
    input.focus();
  }
}

async function uploadEncryptedFile(bytes) {
  if (!state.cloud) {
    const { fileId } = await api.raw('/files', bytes);
    return fileId;
  }

  // В облаке тело запроса к Vercel Function ограничено 4.5 МБ, поэтому
  // шифротекст уходит напрямую в приватный Vercel Blob по подписанной ссылке.
  const ticket = await api.post('/files/ticket', { size: bytes.byteLength });
  const response = await fetch(ticket.uploadUrl, {
    method: 'PUT',
    headers: {
      'x-vercel-blob-access': 'private',
      'x-content-type': 'application/octet-stream',
    },
    body: bytes,
  });
  if (!response.ok) throw new Error('upload_failed');
  const done = await api.post('/files/complete', { fileId: ticket.fileId });
  if (!done || !done.fileId) throw new Error('upload_failed');
  return done.fileId;
}

async function sendFile(file) {
  const chat = chatOfActive();
  if (!chat || !chat.peer || !chat.peer.publicKey) return;
  if (file.size > 25 * 1024 * 1024) {
    ui.toast('Файл больше 25 МБ', 'error');
    return;
  }

  ui.toast('Шифруем файл…', 'info', 1600);
  try {
    const buffer = await file.arrayBuffer();
    const encrypted = await crypto.encryptBytes(buffer);
    const fileId = await uploadEncryptedFile(encrypted.data);
    await sendMessage(
      chat,
      'file',
      {
        file: {
          id: fileId,
          name: file.name,
          size: file.size,
          mime: file.type || 'application/octet-stream',
          key: encrypted.key,
          iv: encrypted.iv,
        },
      },
      { fileId },
    );
  } catch {
    ui.toast('Не удалось отправить файл', 'error');
  }
}

/* ============================== Голосовые ============================= */

let recording = null;

function updateRecordingTimer() {
  if (!recording) return;
  const elapsed = (Date.now() - recording.startedAt) / 1000;
  $('rec-time').textContent = ui.formatDuration(elapsed);
  const wave = $('rec-wave');
  const bar = document.createElement('i');
  bar.style.height = `${5 + Math.random() * 22}px`;
  wave.appendChild(bar);
  while (wave.children.length > 44) wave.firstChild.remove();
}

async function startRecording() {
  if (recording) return;
  if (!navigator.mediaDevices || !window.MediaRecorder) {
    ui.toast('Запись недоступна в этом браузере', 'error');
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mime = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
      ? 'audio/webm;codecs=opus'
      : MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')
        ? 'audio/ogg;codecs=opus'
        : '';
    const recorder = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    const chunks = [];
    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size) chunks.push(event.data);
    };
    recording = {
      recorder,
      stream,
      chunks,
      startedAt: Date.now(),
      mime: recorder.mimeType || mime || 'audio/webm',
      timer: null,
    };
    recorder.start(200);
    $('rec-wave').innerHTML = '';
    $('rec-time').textContent = '0:00';
    $('composer').hidden = true;
    $('recorder').hidden = false;
    recording.timer = setInterval(updateRecordingTimer, 180);
  } catch {
    ui.toast('Нет доступа к микрофону', 'error');
  }
}

async function finishRecording(send) {
  if (!recording) return;
  const session = recording;
  recording = null;
  clearInterval(session.timer);

  const duration = (Date.now() - session.startedAt) / 1000;
  const stopped = new Promise((resolve) => {
    session.recorder.onstop = resolve;
  });
  try {
    session.recorder.stop();
  } catch {
    /* уже остановлен */
  }
  await stopped;
  for (const track of session.stream.getTracks()) track.stop();

  $('recorder').hidden = true;
  $('composer').hidden = false;

  if (!send) return;
  if (duration < 0.8) {
    ui.toast('Запись слишком короткая');
    return;
  }

  const chat = chatOfActive();
  if (!chat || !chat.peer || !chat.peer.publicKey) return;

  try {
    const blob = new Blob(session.chunks, { type: session.mime.split(';')[0] });
    const buffer = await blob.arrayBuffer();
    const encrypted = await crypto.encryptBytes(buffer);
    const fileId = await uploadEncryptedFile(encrypted.data);
    await sendMessage(
      chat,
      'voice',
      {
        voice: {
          id: fileId,
          size: blob.size,
          mime: session.mime,
          key: encrypted.key,
          iv: encrypted.iv,
          duration: Math.round(duration),
        },
      },
      { fileId },
    );
  } catch {
    ui.toast('Не удалось отправить голосовое', 'error');
  }
}

/* ================================ Шапка =============================== */

function renderHeader() {
  const chat = chatOfActive();
  if (!chat) return;
  const peer = chat.peer;
  ui.paintAvatar($('peer-avatar'), peer, {
    showPresence: true,
    online: isPeerOnline(peer),
  });
  $('peer-name').textContent = peerName(peer);

  const status = $('peer-status');
  const online = isPeerOnline(peer);
  status.className = `peer-status${online ? ' online' : ''}`;
  status.textContent = online ? 'в сети' : 'не в сети';

  $('btn-audio-call').disabled = !peer;
  $('btn-video-call').disabled = !peer;
}

async function markRead(chatId) {
  const chat = state.chatMap.get(chatId);
  if (!chat) return;
  try {
    const res = await api.post(`/chats/${chatId}/read`, {});
    chat.myLastRead = res.upTo;
    chat.unread = 0;
    renderChatList();
  } catch {
    /* не критично */
  }
}

/* ================================ Звонки ============================== */

let callTimer = null;

function startCallTimer(activeAt) {
  clearInterval(callTimer);
  const tick = () => {
    const seconds = Math.floor((Date.now() - (activeAt || Date.now())) / 1000);
    $('call-timer').textContent = ui.formatDuration(seconds);
  };
  tick();
  callTimer = setInterval(tick, 1000);
}

function stopCallTimer() {
  clearInterval(callTimer);
  callTimer = null;
}

function renderCall(snapshot) {
  const overlay = $('call');

  if (snapshot.status === 'idle') {
    overlay.hidden = true;
    overlay.dataset.state = 'idle';
    stopCallTimer();
    return;
  }

  overlay.hidden = false;
  overlay.dataset.state = snapshot.status;
  overlay.dataset.video = snapshot.video ? '1' : '0';

  if (!snapshot.peer) return;

  ui.paintAvatar($('call-avatar'), snapshot.peer);
  $('call-name').textContent = peerName(snapshot.peer);

  const statusText = {
    outgoing: snapshot.video ? 'Видеозвонок…' : 'Вызов…',
    incoming: snapshot.video ? 'Входящий видеозвонок' : 'Входящий звонок',
    connecting: 'Соединение…',
    active: 'В сети',
  }[snapshot.status] || '';

  $('call-status').textContent = statusText;
  $('call-bar-incoming').hidden = snapshot.status !== 'incoming';
  $('call-bar-active').hidden = snapshot.status === 'incoming';

  $('call-cam').hidden = !snapshot.video;
  $('call-mic').classList.toggle('off', snapshot.muted);
  $('call-mic').innerHTML = icon(snapshot.muted ? 'mic-off' : 'mic');
  $('call-cam').classList.toggle('off', snapshot.cameraOff);
  $('call-cam').innerHTML = icon(snapshot.cameraOff ? 'video-off' : 'video');

  const local = $('call-local');
  local.srcObject = snapshot.localStream || null;
  local.hidden = !snapshot.video || !snapshot.localStream;
  if (snapshot.localStream) local.play().catch(() => {});

  const remote = $('call-remote');
  if (remote.srcObject !== snapshot.remoteStream) {
    remote.srcObject = snapshot.remoteStream || null;
    if (snapshot.remoteStream) remote.play().catch(() => {});
  }

  if (snapshot.status === 'active') {
    startCallTimer(snapshot.activeAt);
  } else {
    stopCallTimer();
    $('call-timer').textContent = '';
  }
}

const calls = new CallManager({ onUpdate: renderCall });

/* ================================ Модалки ============================= */

function openNewChatModal() {
  ui.openModal({
    title: 'Новый чат',
    body: `
      <p>Введите телефон или Gmail. Собеседник должен быть зарегистрирован в ${ui.escapeHtml(appName)}.</p>
      <div class="field">
        <input id="new-phone" type="text" inputmode="email" autocomplete="off" spellcheck="false"
               placeholder="7 900 000-00-00 или name@gmail.com" maxlength="254">
      </div>
      <div id="lookup-result"></div>
    `,
    actions: [
      { label: 'Отмена', variant: 'ghost' },
      {
        label: 'Найти',
        variant: 'primary',
        onClick: (close) => lookupContact(close),
      },
    ],
    onMount: ({ root, close }) => {
      root.querySelector('#new-phone').addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          lookupContact(close, root);
        }
      });
    },
  });
}

async function lookupContact(close, root = document.querySelector('.modal')) {
  if (!root) return;
  const query = root.querySelector('#new-phone').value.trim();
  const result = root.querySelector('#lookup-result');
  result.innerHTML = '<p style="opacity:.6">Ищем пользователя…</p>';

  try {
    const { user } = await api.get(`/contacts/lookup?query=${encodeURIComponent(query)}`);
    result.innerHTML = `
      <div class="person-card">
        <div class="avatar" id="found-avatar"></div>
        <div>
          <div class="person-name"></div>
          <div class="person-phone"></div>
        </div>
      </div>
      <button class="btn btn-primary" id="btn-open-found" style="width:100%">Написать</button>
    `;
    ui.paintAvatar(result.querySelector('#found-avatar'), user);
    result.querySelector('.person-name').textContent = peerName(user);
    result.querySelector('.person-phone').textContent = contactLabel(user);

    result.querySelector('#btn-open-found').addEventListener('click', async () => {
      try {
        const res = await api.post('/chats', { peerId: user.id });
        close();
        await loadChats();
        openChat(res.chat.id);
      } catch {
        ui.toast('Не удалось открыть чат', 'error');
      }
    });
  } catch {
    result.innerHTML = '<p style="color:#ffadb9">Пользователь с таким телефоном или Gmail не найден.</p>';
  }
}

async function openChatInfo() {
  const chat = chatOfActive();
  if (!chat || !chat.peer) return;
  const peer = chat.peer;

  ui.openModal({
    title: 'Шифрование чата',
    body: `
      <div class="person-card">
        <div class="avatar avatar-lg" id="info-avatar"></div>
        <div>
          <div class="person-name" id="info-name"></div>
          <div class="person-phone" id="info-phone"></div>
        </div>
      </div>
      <p>Код безопасности — отпечаток ваших ключей. Сверьте его с собеседником лично: одинаковые коды означают, что переписку не перехватывают.</p>
      <div class="fingerprint" id="fingerprint">вычисляем…</div>
      <p style="font-size:12px;color:var(--muted);margin-bottom:0">
        Security Cipher v1 · ECDH P-256 → HKDF-SHA256 → AES-256-GCM.<br>
        Ключи хранятся только на устройстве и не отправляются на сервер.
      </p>
    `,
    actions: [{ label: 'Закрыть', variant: 'ghost' }],
    onMount: async ({ root }) => {
      ui.paintAvatar(root.querySelector('#info-avatar'), peer);
      root.querySelector('#info-name').textContent = peerName(peer);
      root.querySelector('#info-phone').textContent = contactLabel(peer);
      const target = root.querySelector('#fingerprint');
      if (!peer.publicKey) {
        target.textContent = 'У собеседника ещё нет ключа шифрования';
        return;
      }
      const groups = await crypto.safetyNumber(state.identity.publicKey, peer.publicKey);
      const rows = [];
      for (let i = 0; i < groups.length; i += 4) rows.push(groups.slice(i, i + 4).join(' '));
      target.innerHTML = rows.map((row) => ui.escapeHtml(row)).join('<br>');
    },
  });
}

function openProfileModal() {
  ui.openModal({
    title: 'Профиль',
    body: `
      <div class="modal-tabs">
        <button type="button" class="modal-tab active" data-tab="profile">Профиль</button>
        <button type="button" class="modal-tab" data-tab="security">Безопасность</button>
      </div>

      <div class="tab-panel" data-panel="profile">
        <p>Имя видят собеседники.</p>
        <div class="field">
          <input id="profile-name" type="text" maxlength="64" placeholder="Ваше имя" autocomplete="name">
        </div>
        <div class="profile-avatar">
          <div class="avatar avatar-lg" id="profile-avatar-preview"></div>
          <div class="field">
            <label class="label" style="font-size:12px;margin-bottom:4px">Фото профиля (аватарка)</label>
            <input id="profile-avatar-file" type="file" accept="image/*">
          </div>
          <button class="btn btn-ghost" id="profile-avatar-upload" style="width:100%">Загрузить аватарку</button>
        </div>
        <p style="font-size:13px;margin:10px 0 0;color:var(--muted)">
          ${ui.escapeHtml(contactLabel(state.me))}
        </p>
      </div>

      <div class="tab-panel" data-panel="security" hidden>
        <p>Постоянный код доступа. Его нужно вводить при каждом повторном входе на этот номер или Gmail.</p>
        <div class="access-code-box"><span id="security-code-value">Загрузка…</span></div>
        <p class="hint" id="security-code-updated"></p>
        <div class="security-actions">
          <button type="button" class="btn btn-ghost" id="security-copy">Скопировать</button>
          <button type="button" class="btn btn-ghost" id="security-rotate">Сменить код</button>
        </div>
        <p class="hint">Если код узнал кто-то другой, смените его: старый код сразу перестанет работать.</p>
        ${betaMode ? '<p class="hint beta-hint">Бета-режим: код входа при подтверждении номера показывается прямо на экране.</p>' : ''}
      </div>
    `,
    actions: [
      { label: 'Закрыть', variant: 'ghost' },
      {
        label: 'Сохранить',
        variant: 'primary',
        onClick: async (close, button) => {
          const input = document.querySelector('#profile-name');
          const name = input ? input.value.trim() : '';
          if (!name) {
            ui.toast('Имя не может быть пустым', 'error');
            return;
          }
          button.disabled = true;
          try {
            const res = await api.patch('/me', { name });
            state.me = res.user;
            $('me-name').textContent = state.me.name;
            ui.paintAvatar($('me-avatar'), state.me);
            close();
            ui.toast('Имя обновлено');
            await loadChats();
          } catch {
            ui.toast('Не удалось сохранить имя', 'error');
          } finally {
            button.disabled = false;
          }
        },
      },
    ],
    onMount: ({ root, close }) => {
      const input = root.querySelector('#profile-name');
      input.value = state.me.name;

      const saveButton = root.querySelector('.modal-actions .btn-primary');
      const tabs = [...root.querySelectorAll('.modal-tab')];
      const panels = [...root.querySelectorAll('.tab-panel')];

      let securityCode = '';
      const codeValue = root.querySelector('#security-code-value');
      const codeUpdated = root.querySelector('#security-code-updated');
      const copyBtn = root.querySelector('#security-copy');
      const rotateBtn = root.querySelector('#security-rotate');

      const paintCode = () => {
        codeValue.textContent = securityCode ? formatAccessCode(securityCode) : '—';
      };

      const loadSecurity = async () => {
        if (!root.isConnected) return;
        try {
          const info = await api.get('/me/security');
          if (!root.isConnected) return;
          securityCode = normalizeAccessInput(info.accessCode);
          paintCode();
          codeUpdated.textContent = info.updatedAt
            ? `Создан: ${new Date(info.updatedAt).toLocaleString('ru-RU')}`
            : '';
        } catch {
          if (!root.isConnected) return;
          codeValue.textContent = 'Не удалось загрузить';
          ui.toast('Не удалось получить код доступа', 'error');
        }
      };

      const switchTab = (name) => {
        tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === name));
        panels.forEach((panel) => {
          panel.hidden = panel.dataset.panel !== name;
        });
        if (saveButton) saveButton.hidden = name !== 'profile';
        if (name === 'security') loadSecurity();
      };

      tabs.forEach((tab) => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
      });

      copyBtn.addEventListener('click', async () => {
        if (!securityCode) await loadSecurity();
        if (!securityCode) return;
        const ok = await copyText(formatAccessCode(securityCode));
        ui.toast(ok ? 'Код доступа скопирован' : 'Не удалось скопировать код', ok ? 'info' : 'error');
      });

      rotateBtn.addEventListener('click', () => {
        ui.openModal({
          title: 'Сменить код доступа?',
          body: '<p>Старый код сразу перестанет работать. Незавершённые входы по нему будут сброшены.</p>',
          actions: [
            { label: 'Отмена', variant: 'ghost' },
            {
              label: 'Сменить',
              variant: 'danger',
              onClick: async (closeConfirm, button) => {
                button.disabled = true;
                try {
                  const res = await api.post('/me/access-code/rotate', {});
                  securityCode = normalizeAccessInput(res.accessCode);
                  paintCode();
                  codeUpdated.textContent = res.updatedAt
                    ? `Обновлён: ${new Date(res.updatedAt).toLocaleString('ru-RU')}`
                    : '';
                  closeConfirm();
                  ui.toast('Код доступа изменён');
                } catch {
                  ui.toast('Не удалось сменить код', 'error');
                  button.disabled = false;
                }
              },
            },
          ],
        });
      });

      const preview = root.querySelector('#profile-avatar-preview');
      ui.paintAvatar(preview, state.me);

      const fileInput = root.querySelector('#profile-avatar-file');
      const uploadBtn = root.querySelector('#profile-avatar-upload');
      let chosenFile = null;

      fileInput.addEventListener('change', (event) => {
        const file = event.target.files && event.target.files[0];
        chosenFile = file || null;
        if (file) {
          const url = URL.createObjectURL(file);
          preview.style.background = '';
          preview.innerHTML = `<img src="${url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;display:block">`;
          const img = preview.querySelector('img');
          if (img) img.addEventListener('load', () => URL.revokeObjectURL(url), { once: true });
        }
      });

      uploadBtn.addEventListener('click', async () => {
        if (!chosenFile) {
          ui.toast('Выберите файл картинки', 'error');
          return;
        }
        if (chosenFile.size > 2 * 1024 * 1024) {
          ui.toast('Картинка больше 2 МБ', 'error');
          return;
        }
        uploadBtn.disabled = true;
        try {
          const buffer = await chosenFile.arrayBuffer();
          const res = await api.raw('/me/avatar', buffer);
          if (res && res.user) {
            state.me = res.user;
            $('me-name').textContent = state.me.name;
            ui.paintAvatar($('me-avatar'), state.me);
            ui.paintAvatar(preview, state.me);
            close();
            ui.toast('Аватарка обновлена');
            await loadChats();
          }
        } catch {
          ui.toast('Не удалось загрузить аватарку', 'error');
        } finally {
          uploadBtn.disabled = false;
        }
      });
    },
  });
}

/* ============================== Обработчики =========================== */

function bindApp() {
  $('btn-new-chat').addEventListener('click', openNewChatModal);
  $('btn-empty-new').addEventListener('click', openNewChatModal);

  $('chat-search').addEventListener('input', (event) => {
    state.search = event.target.value;
    renderChatList();
  });

  $('chat-list').addEventListener('click', (event) => {
    const item = event.target.closest('.chat-item');
    if (item) openChat(item.dataset.id);
  });

  $('btn-back').addEventListener('click', () => {
    $('app').classList.remove('chat-open');
    state.activeId = null;
    stopVoice();
  });

  $('me-info').addEventListener('click', openProfileModal);

  $('btn-logout').addEventListener('click', () => {
    ui.openModal({
      title: 'Выйти из аккаунта?',
      body: '<p>Ключи шифрования останутся на этом устройстве — история будет доступна после повторного входа.</p>',
      actions: [
        { label: 'Отмена', variant: 'ghost' },
        {
          label: 'Выйти',
          variant: 'danger',
          onClick: async () => {
            try {
              await api.post('/auth/logout', {});
            } catch {
              /* игнорируем */
            }
            setToken(null);
            if (state.events) state.events.close();
            location.reload();
          },
        },
      ],
    });
  });

  $('btn-send').addEventListener('click', sendText);
  $('btn-attach').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', async (event) => {
    const file = event.target.files && event.target.files[0];
    event.target.value = '';
    if (file) await sendFile(file);
  });

  $('btn-voice').addEventListener('click', startRecording);
  $('btn-rec-send').addEventListener('click', () => finishRecording(true));
  $('btn-rec-cancel').addEventListener('click', () => finishRecording(false));

  const input = $('msg-input');
  input.addEventListener('input', () => {
    autoGrow();
    updateSendVisibility();
    maybeTyping();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      sendText();
    }
  });

  $('messages').addEventListener('scroll', () => {
    const el = $('messages');
    if (el.scrollTop < 60 && state.hasMore && !state.loadingOlder) loadOlder();
  });

  $('btn-audio-call').addEventListener('click', () => {
    const chat = chatOfActive();
    if (!chat || !chat.peer) return;
    calls.start(chat.peer, { video: false });
  });

  $('btn-video-call').addEventListener('click', () => {
    const chat = chatOfActive();
    if (!chat || !chat.peer) return;
    calls.start(chat.peer, { video: true });
  });

  $('btn-chat-info').addEventListener('click', openChatInfo);

  $('call-accept').addEventListener('click', () => calls.accept());
  $('call-decline').addEventListener('click', () => calls.reject());
  $('call-hangup').addEventListener('click', () => calls.hangup());
  $('call-mic').addEventListener('click', () => calls.toggleMic());
  $('call-cam').addEventListener('click', () => calls.toggleCamera());

  window.addEventListener('security:unauthorized', () => {
    if (!state.me) return;
    setToken(null);
    if (state.events) state.events.close();
    ui.toast('Сессия истекла. Войдите снова.', 'error');
    setTimeout(() => location.reload(), 900);
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible' || !state.me) return;
    if (state.activeId) markRead(state.activeId);
    syncFromServer();
  });
}

function maybeTyping() {
  const chat = chatOfActive();
  if (!chat) return;
  const now = Date.now();
  if (now - state.typingSentAt < 2400) return;
  state.typingSentAt = now;
  api.post(`/chats/${chat.id}/typing`, {}).catch(() => {});
}

/* ================================ Старт =============================== */

async function boot() {
  bindAuth();
  bindApp();

  const hash = new URLSearchParams(location.search).get('chat');
  if (hash) pendingOpenChat = hash;

  try {
    const cfg = await api.get('/config').catch(() => ({ appName: 'Security' }));
    betaMode = !!cfg.betaMode;
    state.cloud = !!cfg.cloud;
    applyBranding(cfg.appName);
    applyAuthMode(cfg.authMode, betaMode);
  } catch {
    applyBranding('Security');
  }

  if (!api.token) {
    resetAuthForms();
    return;
  }

  try {
    const res = await api.get('/me');
    state.me = res.user;
    await enterApp();
  } catch {
    setToken(null);
    resetAuthForms();
  }
}

boot();
