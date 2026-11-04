'use strict';

/**
 * Шина реального времени поверх Server-Sent Events.
 * Держит открытые соединения и рассылает события конкретным пользователям.
 */

const clients = new Map(); // userId -> Set<res>
let presenceListener = null;

function add(userId, res) {
  let set = clients.get(userId);
  if (!set) {
    set = new Set();
    clients.set(userId, set);
  }
  const first = set.size === 0;
  set.add(res);
  if (first) {
    emitPresence(userId, true);
  }
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
  const set = clients.get(userId);
  if (!set) return 0;
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
  return delivered;
}

function sendAll(userIds, event, data) {
  let delivered = 0;
  for (const id of new Set(userIds)) delivered += send(id, event, data);
  return delivered;
}

function isOnline(userId) {
  return clients.has(userId);
}

function onlineUsers() {
  return Array.from(clients.keys());
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

setInterval(heartbeat, 25000).unref();

module.exports = {
  add,
  remove,
  send,
  sendAll,
  isOnline,
  onlineUsers,
  subscribePresence,
};
