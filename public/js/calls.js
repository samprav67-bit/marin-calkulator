'use strict';

import { api } from './api.js';
import * as ui from './ui.js';

const { $, icon } = ui;

const ICE_SERVERS = [
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
];

/**
 * Управление WebRTC-звонком: микрофон/камера, offer/answer, ICE,
 * переключение дорожек и завершение. Сигнализация идёт через /api/calls/signal.
 */
export class CallManager {
  constructor({ onUpdate } = {}) {
    this.onUpdate = onUpdate || (() => {});
    this.reset();
  }

  reset() {
    this.status = 'idle';
    this.peer = null;
    this.callId = null;
    this.video = false;
    this.muted = false;
    this.cameraOff = false;
    this.pc = null;
    this.localStream = null;
    this.remoteStream = null;
    this.pendingIce = [];
    this.remoteDescSet = false;
    this.pendingOffer = null;
    this.ringTimer = null;
    this.activeAt = null;
  }

  get busy() {
    return this.status !== 'idle';
  }

  snapshot() {
    return {
      status: this.status,
      peer: this.peer,
      video: this.video,
      muted: this.muted,
      cameraOff: this.cameraOff,
      localStream: this.localStream,
      remoteStream: this.remoteStream,
      activeAt: this.activeAt,
    };
  }

  emit() {
    this.onUpdate(this.snapshot());
  }

  async send(call, targetId) {
    const to = targetId || (this.peer && this.peer.id);
    if (!to) return null;
    try {
      return await api.post('/calls/signal', { to, call });
    } catch {
      return null;
    }
  }

  async prepareMedia() {
    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true },
        video: this.video
          ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' }
          : false,
      });
    } catch (err) {
      if (this.video) {
        this.video = false;
        this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        ui.toast('Камера недоступна — звонок только со звуком');
      } else {
        throw err;
      }
    }
    this.emit();
  }

  createPeerConnection() {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS, iceCandidatePoolSize: 4 });
    this.pc = pc;
    this.remoteDescSet = false;

    for (const track of this.localStream.getTracks()) {
      pc.addTrack(track, this.localStream);
    }

    pc.onicecandidate = (event) => {
      if (!event.candidate) return;
      this.send({ type: 'ice', callId: this.callId, candidate: event.candidate.toJSON() });
    };

    pc.ontrack = (event) => {
      this.remoteStream = event.streams[0] || new MediaStream([event.track]);
      this.emit();
    };

    pc.onconnectionstatechange = () => {
      if (!this.pc) return;
      const state = this.pc.connectionState;
      if (state === 'connected' && this.status !== 'active') {
        this.status = 'active';
        this.activeAt = Date.now();
        clearTimeout(this.ringTimer);
        this.emit();
      }
      if (state === 'failed') {
        this.stop(false);
        ui.toast('Соединение прервано', 'error');
      }
    };

    return pc;
  }

  async start(peer, { video = false } = {}) {
    if (this.busy) return;
    this.reset();
    this.peer = peer;
    this.video = !!video;
    this.callId = crypto.randomUUID();
    this.status = 'outgoing';
    this.emit();

    try {
      await this.prepareMedia();
    } catch {
      this.stop(false);
      ui.toast('Нет доступа к микрофону', 'error');
      return;
    }

    this.createPeerConnection();
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);

    const result = await this.send({
      type: 'offer',
      callId: this.callId,
      sdp: this.pc.localDescription.toJSON(),
      media: { video: this.video },
    });

    if (result && result.delivered === false) {
      this.stop(false);
      ui.toast('Собеседник не в сети', 'error');
      return;
    }

    this.ringTimer = setTimeout(() => {
      if (this.status === 'outgoing') {
        this.hangup();
        ui.toast('Собеседник не ответил');
      }
    }, 45000);
  }

  async handleSignal({ from, call }) {
    if (!call || !call.callId) return;

    if (call.type === 'offer') {
      if (this.busy) {
        await this.send({ type: 'busy', callId: call.callId }, from.id);
        return;
      }
      this.reset();
      this.peer = from;
      this.callId = call.callId;
      this.video = !!(call.media && call.media.video);
      this.pendingOffer = call.sdp;
      this.status = 'incoming';
      this.emit();
      return;
    }

    if (call.callId !== this.callId) return;

    if (call.type === 'answer') {
      if (!this.pc) return;
      try {
        await this.pc.setRemoteDescription(call.sdp);
        this.remoteDescSet = true;
        await this.flushIce();
      } catch {
        this.stop(false);
      }
      return;
    }

    if (call.type === 'ice') {
      await this.addIce(call.candidate);
      return;
    }

    if (call.type === 'end') {
      const wasIncoming = this.status === 'incoming';
      this.stop(false);
      ui.toast(wasIncoming ? 'Звонок отменён' : 'Звонок завершён');
      return;
    }

    if (call.type === 'reject') {
      this.stop(false);
      ui.toast('Звонок отклонён');
      return;
    }

    if (call.type === 'busy') {
      this.stop(false);
      ui.toast('Собеседник занят');
    }
  }

  async accept() {
    if (this.status !== 'incoming') return;
    try {
      await this.prepareMedia();
    } catch {
      this.send({ type: 'reject', callId: this.callId });
      this.stop(false);
      ui.toast('Нет доступа к микрофону', 'error');
      return;
    }

    this.status = 'connecting';
    this.emit();
    this.createPeerConnection();

    try {
      await this.pc.setRemoteDescription(this.pendingOffer);
      this.remoteDescSet = true;
      await this.flushIce();
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      await this.send({ type: 'answer', callId: this.callId, sdp: this.pc.localDescription.toJSON() });
    } catch {
      this.stop(true);
      ui.toast('Не удалось установить соединение', 'error');
    }
  }

  reject() {
    if (this.status !== 'incoming') return;
    this.send({ type: 'reject', callId: this.callId });
    this.stop(false);
  }

  hangup() {
    if (!this.busy) return;
    this.stop(true);
  }

  stop(notify) {
    const peer = this.peer;
    const callId = this.callId;
    if (notify && peer && callId) {
      this.send({ type: 'end', callId });
    }
    clearTimeout(this.ringTimer);
    if (this.pc) {
      try {
        this.pc.close();
      } catch {
        /* уже закрыт */
      }
    }
    if (this.localStream) {
      for (const track of this.localStream.getTracks()) track.stop();
    }
    this.reset();
    this.emit();
  }

  async addIce(candidate) {
    if (!candidate) return;
    if (this.pc && this.remoteDescSet) {
      try {
        await this.pc.addIceCandidate(candidate);
      } catch {
        /* устаревший кандидат */
      }
    } else {
      this.pendingIce.push(candidate);
    }
  }

  async flushIce() {
    const queue = this.pendingIce.splice(0);
    for (const candidate of queue) {
      try {
        await this.pc.addIceCandidate(candidate);
      } catch {
        /* игнорируем */
      }
    }
  }

  toggleMic() {
    if (!this.localStream) return;
    this.muted = !this.muted;
    for (const track of this.localStream.getAudioTracks()) track.enabled = !this.muted;
    this.emit();
  }

  toggleCamera() {
    if (!this.localStream || !this.video) return;
    this.cameraOff = !this.cameraOff;
    for (const track of this.localStream.getVideoTracks()) track.enabled = !this.cameraOff;
    this.emit();
  }
}
