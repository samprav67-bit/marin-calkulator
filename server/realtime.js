'use strict';

/**
 * Шина событий.
 *
 * Локально: держит SSE-соединения и дополнительно пишет события в журнал,
 * чтобы клиент мог работать через polling.
 *
 * В облаке: SSE-соединения не используются, события складываются в журнал
 * state.events и забираются клиентом через /api/events/poll.
 */

const store = require('./store');
const { db } = store;

const clients = new Map(); // userId -> Set<res> (только локальный режим)
let presenceListener = null;

function recent(userId) {
  const user = db.users[userId];
  if (!user || !user.lastSeenAt) return false;
  const at = Date.parse(user.lastSeenAt);
  return Number.isFinite(at) && Date.now() - at < 120000;
}

function appendEvent(userId, event, data) {
  db.events = Array.isArray(db.events) ? db.events : [];
  db.meta.eventSeq = Number(db.meta.eventSeq) || 0;
  const seq = db.meta.eventSeq + 1;
  db.meta.eventSeq = seq;
  db.events.push({
    seq,
    to: userId,
    type: event,
    data,
    at: new Date().toISOString(),
  });
  if (db.events.length > 800) db.events.splice(0, db.events.length - 800);
  store.save();
  return seq;
}

function add(userId, res) {
  let set = clients.get(userId);
  if (!set) {
    set = new Set();
    clients.set(userId, set);
  }
  const first = set.size === 0;
  set.add(res);
  if (first) emitPresence(userId, true);
  return () => remove(userId, res);
}

function remove(userId, res) {
  const set = clients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) {
    clients.delete(userId);
    emitPresence(userId, false);
  }
}

function emitPresence(userId, online) {
  if (presenceListener) presenceListener(userId, online);
}

function subscribePresence(listener) {
  presenceListener = listener;
}

function send(userId, event, data) {
  appendEvent(userId, event, data);

  const set = clients.get(userId);
  if (!set || !set.size) return 1;

  const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  let delivered = 0;
  for (const res of set) {
    try {
      res.write(frame);
      delivered += 1;
    } catch {
      set.delete(res);
    }
  }
  return Math.max(1, delivered);
}

function sendAll(userIds, event, data) {
  let delivered = 0;
  for (const id of new Set(userIds)) delivered += send(id, event, data);
  return delivered;
}

function isOnline(userId) {
  return clients.has(userId) || recent(userId);
}

function onlineUsers() {
  const ids = new Set(clients.keys());
  for (const user of Object.values(db.users)) {
    if (recent(user.id)) ids.add(user.id);
  }
  return Array.from(ids);
}

function heartbeat() {
  for (const set of clients.values()) {
    for (const res of set) {
      try {
        res.write(': ping\n\n');
      } catch {
        /* соединение уже закрыто */
      }
    }
  }
}

if (!store.isCloud) setInterval(heartbeat, 25000).unref();

module.exports = {
  add,
  remove,
  send,
  sendAll,
  isOnline,
  onlineUsers,
  subscribePresence,
};
