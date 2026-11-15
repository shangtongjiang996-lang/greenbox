'use strict';

const { kvGet, kvUpdate } = require('./redis');
const { writeAudit } = require('./audit');

const WRITE_ACTIONS = new Set(['post', 'comment', 'dm', 'feedback', 'tool', 'report']);

async function getModerationState(username) {
  const state = await kvGet(`moderation:${username}`);
  if (!state || typeof state !== 'object') return { warnings: 0, mutedUntil: 0, bannedUntil: 0, reason: '' };
  return {
    warnings: Number(state.warnings) || 0,
    mutedUntil: Number(state.mutedUntil) || 0,
    bannedUntil: Number(state.bannedUntil) || 0,
    reason: String(state.reason || ''),
    updatedAt: state.updatedAt || 0,
  };
}

function untilText(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString('zh-CN');
}

async function checkModeration(username, action) {
  if (!username || username === 'admin') return null;
  const state = await getModerationState(username);
  const now = Date.now();
  if (state.bannedUntil > now) {
    return `账号已被封禁，解除时间：${untilText(state.bannedUntil)}`;
  }
  if (WRITE_ACTIONS.has(action) && state.mutedUntil > now) {
    return `账号已被禁言，解除时间：${untilText(state.mutedUntil)}`;
  }
  return null;
}

async function applyModeration(username, action, durationHours, reason, actor) {
  const hours = Math.max(1, Math.min(24 * 365, Number(durationHours) || 24));
  const now = Date.now();
  const next = await kvUpdate(`moderation:${username}`, current => {
    const state = current && typeof current === 'object'
      ? Object.assign({ warnings: 0, mutedUntil: 0, bannedUntil: 0, reason: '' }, current)
      : { warnings: 0, mutedUntil: 0, bannedUntil: 0, reason: '' };
    if (action === 'warn') {
      state.warnings = (Number(state.warnings) || 0) + 1;
    } else if (action === 'mute') {
      state.mutedUntil = Math.max(Number(state.mutedUntil) || 0, now) + hours * 3600 * 1000;
    } else if (action === 'ban') {
      state.bannedUntil = Math.max(Number(state.bannedUntil) || 0, now) + hours * 3600 * 1000;
    } else if (action === 'unmute') {
      state.mutedUntil = 0;
    } else if (action === 'unban') {
      state.bannedUntil = 0;
    }
    state.reason = String(reason || state.reason || '').slice(0, 500);
    state.updatedAt = now;
    return state;
  }, {});

  await writeAudit(actor || 'admin', `moderation:${action}`, username,
    String(reason || '').slice(0, 500), { durationHours: hours });
  return next;
}

module.exports = {
  getModerationState,
  checkModeration,
  applyModeration,
  untilText,
};
