'use strict';

const { kvGet, kvUpdate } = require('./redis');
const { writeAudit } = require('./audit');

const WRITE_ACTIONS = new Set(['post', 'comment', 'dm', 'feedback', 'tool', 'report']);
const MAX_DURATION_MS = 365 * 24 * 3600 * 1000;

function emptyState() {
  return {
    warnings: 0,
    mutedFrom: 0,
    mutedUntil: 0,
    bannedFrom: 0,
    bannedUntil: 0,
    reason: '',
    banReason: '',
    muteReason: '',
    activeBanId: '',
    activeMuteId: '',
    records: [],
    updatedAt: 0,
  };
}

function normalizeState(raw) {
  const state = Object.assign(emptyState(), raw && typeof raw === 'object' ? raw : {});
  state.warnings = Number(state.warnings) || 0;
  state.mutedFrom = Number(state.mutedFrom) || 0;
  state.mutedUntil = Number(state.mutedUntil) || 0;
  state.bannedFrom = Number(state.bannedFrom) || 0;
  state.bannedUntil = Number(state.bannedUntil) || 0;
  state.reason = String(state.reason || '');
  state.banReason = String(state.banReason || state.reason || '');
  state.muteReason = String(state.muteReason || state.reason || '');
  state.activeBanId = String(state.activeBanId || '');
  state.activeMuteId = String(state.activeMuteId || '');
  state.records = Array.isArray(state.records) ? state.records.slice(-100) : [];
  state.updatedAt = Number(state.updatedAt) || 0;
  return state;
}

async function getModerationState(username) {
  const raw = await kvGet(`moderation:${username}`);
  const state = normalizeState(raw);
  const now = Date.now();
  state.activeBan = !!(state.bannedUntil > now && (!state.bannedFrom || state.bannedFrom <= now));
  state.activeMute = !!(state.mutedUntil > now && (!state.mutedFrom || state.mutedFrom <= now));
  state.upcomingBan = !!(state.bannedFrom > now && state.bannedUntil > state.bannedFrom);
  state.upcomingMute = !!(state.mutedFrom > now && state.mutedUntil > state.mutedFrom);
  state.banText = state.bannedUntil ? untilText(state.bannedUntil) : '';
  state.muteText = state.mutedUntil ? untilText(state.mutedUntil) : '';
  return state;
}

function untilText(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
}

async function checkModeration(username, action) {
  if (!username || username === 'admin') return null;
  const state = await getModerationState(username);
  if (state.activeBan) {
    return `账号已被封禁，解除时间：${state.banText}${state.banReason ? '，原因：' + state.banReason : ''}`;
  }
  if (WRITE_ACTIONS.has(action) && state.activeMute) {
    return `账号已被禁言，解除时间：${state.muteText}${state.muteReason ? '，原因：' + state.muteReason : ''}`;
  }
  return null;
}

function parseOptions(durationOrOptions) {
  if (durationOrOptions && typeof durationOrOptions === 'object' && !Array.isArray(durationOrOptions)) {
    const now = Date.now();
    let startAt = Number(durationOrOptions.startAt) || now;
    let endAt = Number(durationOrOptions.endAt) || 0;
    if (!endAt && durationOrOptions.durationDays) endAt = startAt + Number(durationOrOptions.durationDays) * 24 * 3600 * 1000;
    if (!endAt && durationOrOptions.durationHours) endAt = startAt + Number(durationOrOptions.durationHours) * 3600 * 1000;
    if (!endAt) endAt = startAt + 24 * 3600 * 1000;
    return { startAt, endAt };
  }
  const now = Date.now();
  const hours = Math.max(1, Math.min(24 * 365, Number(durationOrOptions) || 24));
  return { startAt: now, endAt: now + hours * 3600 * 1000 };
}

async function applyModeration(username, action, durationOrOptions, reason, actor) {
  const now = Date.now();
  const cleanReason = String(reason || '').replace(/[<>]/g, '').trim().slice(0, 500);
  if ((action === 'mute' || action === 'ban') && !cleanReason) {
    const err = new Error('禁言或封禁必须填写理由');
    err.code = 'REASON_REQUIRED';
    throw err;
  }
  let timing = null;
  if (action === 'mute' || action === 'ban') {
    timing = parseOptions(durationOrOptions);
    if (!Number.isFinite(timing.startAt) || !Number.isFinite(timing.endAt) || timing.endAt <= timing.startAt) {
      const err = new Error('处罚结束时间必须晚于开始时间');
      err.code = 'INVALID_TIME';
      throw err;
    }
    if (timing.endAt - timing.startAt > MAX_DURATION_MS) {
      const err = new Error('处罚时长不能超过 365 天');
      err.code = 'INVALID_TIME';
      throw err;
    }
  }

  const next = await kvUpdate(`moderation:${username}`, current => {
    const state = normalizeState(current);
    state.updatedAt = now;
    if (action === 'warn') {
      state.warnings += 1;
      state.reason = cleanReason || state.reason;
      state.records.push({
        id: 'md_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        type: 'warn',
        reason: cleanReason,
        startAt: now,
        endAt: 0,
        createdAt: now,
        actor: actor || 'admin',
        revokedAt: 0,
      });
    } else if (action === 'mute' || action === 'ban') {
      const isBan = action === 'ban';
      const id = 'md_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      state.records.push({
        id,
        type: action,
        reason: cleanReason,
        startAt: timing.startAt,
        endAt: timing.endAt,
        createdAt: now,
        actor: actor || 'admin',
        revokedAt: 0,
      });
      if (isBan) {
        state.bannedFrom = timing.startAt;
        state.bannedUntil = timing.endAt;
        state.banReason = cleanReason;
        state.activeBanId = id;
        state.reason = cleanReason || state.reason;
      } else {
        state.mutedFrom = timing.startAt;
        state.mutedUntil = timing.endAt;
        state.muteReason = cleanReason;
        state.activeMuteId = id;
        state.reason = cleanReason || state.reason;
      }
    } else if (action === 'unmute') {
      state.mutedFrom = 0;
      state.mutedUntil = 0;
      state.muteReason = '';
      revokeRecord(state, state.activeMuteId, actor, cleanReason || '管理员解除禁言');
      state.activeMuteId = '';
    } else if (action === 'unban') {
      state.bannedFrom = 0;
      state.bannedUntil = 0;
      state.banReason = '';
      revokeRecord(state, state.activeBanId, actor, cleanReason || '管理员解除封禁');
      state.activeBanId = '';
    }
    return state;
  }, emptyState());

  await writeAudit(actor || 'admin', `moderation:${action}`, username, cleanReason, {
    startAt: timing && timing.startAt,
    endAt: timing && timing.endAt,
  });
  return getModerationState(username);
}

function revokeRecord(state, id, actor, reason) {
  if (!id) return;
  const record = state.records.find(r => r && r.id === id);
  if (!record || record.revokedAt) return;
  record.revokedAt = Date.now();
  record.revokedBy = actor || 'admin';
  record.revokeReason = String(reason || '').slice(0, 500);
}

async function revokeModeration(username, recordId, actor, reason) {
  const next = await kvUpdate(`moderation:${username}`, current => {
    const state = normalizeState(current);
    const record = state.records.find(r => r && r.id === recordId);
    if (!record || record.revokedAt) return state;
    record.revokedAt = Date.now();
    record.revokedBy = actor || 'admin';
    record.revokeReason = String(reason || '').replace(/[<>]/g, '').trim().slice(0, 500);
    if (record.type === 'ban' && state.activeBanId === record.id) {
      state.bannedFrom = 0;
      state.bannedUntil = 0;
      state.banReason = '';
      state.activeBanId = '';
    }
    if (record.type === 'mute' && state.activeMuteId === record.id) {
      state.mutedFrom = 0;
      state.mutedUntil = 0;
      state.muteReason = '';
      state.activeMuteId = '';
    }
    state.updatedAt = Date.now();
    return state;
  }, emptyState());
  await writeAudit(actor || 'admin', 'moderation:revoke', username, recordId, { reason });
  return getModerationState(username);
}

module.exports = {
  getModerationState,
  checkModeration,
  applyModeration,
  revokeModeration,
  untilText,
};
