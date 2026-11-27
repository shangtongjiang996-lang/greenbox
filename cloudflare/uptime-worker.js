/**
 * GreenBox uptime monitor — Cloudflare Worker
 *
 * Cron: every 5 minutes (UTC)
 * Night window: 23:00–06:00 Asia/Shanghai is skipped.
 *
 * Bindings:
 *   UPTIME_KV    KV namespace
 *
 * Variables / secrets:
 *   TARGET_URL              optional, default https://greenboxhweb.com/api/health
 *   MONITOR_TOKEN           optional, for POST /run
 */

const TIME_ZONE = 'Asia/Shanghai';
const DEFAULT_TARGET = 'https://greenboxhweb.com/api/health';
const DAY_MS = 24 * 60 * 60 * 1000;
const RETENTION_SECONDS = 40 * 24 * 60 * 60;
const MAX_CHECKS_PER_DAY = 288;

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: Object.assign({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    }, corsHeaders(), extra || {}),
  });
}

function localParts(timestamp) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(new Date(timestamp));
  const out = {};
  for (const p of parts) if (p.type !== 'literal') out[p.type] = p.value;
  return {
    date: `${out.year}-${out.month}-${out.day}`,
    hour: Number(out.hour),
    minute: Number(out.minute),
  };
}

function isNight(timestamp) {
  const h = localParts(timestamp).hour;
  return h >= 23 || h < 6;
}

function dateKeyForOffset(offsetDays) {
  return localParts(Date.now() - offsetDays * DAY_MS).date;
}

async function readDay(env, date) {
  const raw = await env.UPTIME_KV.get(`check:${date}`);
  if (!raw) return [];
  try {
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list : [];
  } catch (e) {
    return [];
  }
}

async function appendCheck(env, check) {
  const date = localParts(check.ts).date;
  const list = await readDay(env, date);
  list.push(check);
  const trimmed = list.slice(-MAX_CHECKS_PER_DAY);
  await env.UPTIME_KV.put(`check:${date}`, JSON.stringify(trimmed), {
    expirationTtl: RETENTION_SECONDS,
  });
  return check;
}

async function runCheck(env, options) {
  options = options || {};
  const now = Date.now();
  if (!options.force && isNight(now)) {
    return { skipped: true, reason: 'night', at: now, window: '23:00-06:00 Asia/Shanghai' };
  }

  const target = String(env.TARGET_URL || DEFAULT_TARGET);
  const start = Date.now();
  let status = 0;
  let ok = false;
  let error = '';
  let payload = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    let res;
    try {
      res = await fetch(target, {
        method: 'GET',
        headers: {
          'User-Agent': 'GreenBox-Uptime/1.0',
          'Cache-Control': 'no-cache',
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    status = res.status;
    const text = await res.text();
    try { payload = JSON.parse(text); } catch (e) {}
    const apiError = payload && (payload.error || payload.message);
    ok = res.ok && (!payload || payload.ok !== false);
    if (!res.ok) {
      error = apiError ? String(apiError).slice(0, 300) : `HTTP ${res.status}`;
    }
  } catch (e) {
    error = e && e.name === 'AbortError' ? 'timeout' : (e.message || 'request failed');
  }

  const check = {
    ts: now,
    ok,
    status,
    latency: Date.now() - start,
    error: error || undefined,
    checkedAt: new Date(now).toISOString(),
  };
  await appendCheck(env, check);
  return check;
}

function summarize(checks, rangeMs) {
  const now = Date.now();
  const relevant = checks.filter(c => c && c.ts >= now - rangeMs);
  const up = relevant.filter(c => c.ok).length;
  const down = relevant.filter(c => !c.ok).length;
  const total = up + down;
  const avgLatency = total
    ? Math.round(relevant.reduce((sum, c) => sum + (Number(c.latency) || 0), 0) / total)
    : null;
  return {
    up,
    down,
    total,
    percent: total ? Number(((up / total) * 100).toFixed(2)) : null,
    avgLatency,
    checks: relevant,
  };
}

async function loadRange(env, range) {
  const days = range === '7d' ? 7 : range === '30d' ? 30 : 2;
  const checks = [];
  const daysData = [];
  for (let i = 0; i < days; i++) {
    const date = dateKeyForOffset(i);
    const list = await readDay(env, date);
    const sorted = list.slice().sort((a, b) => a.ts - b.ts);
    checks.push(...sorted);
    const up = sorted.filter(c => c.ok).length;
    const down = sorted.filter(c => !c.ok).length;
    daysData.push({
      date,
      up,
      down,
      total: up + down,
      percent: (up + down) ? Number(((up / (up + down)) * 100).toFixed(2)) : null,
    });
  }
  checks.sort((a, b) => a.ts - b.ts);
  const rangeMs = range === '7d' ? 7 * DAY_MS : range === '30d' ? 30 * DAY_MS : DAY_MS;
  const summary = summarize(checks, rangeMs);
  const latest = checks.length ? checks[checks.length - 1] : null;
  return {
    target: String(env.TARGET_URL || DEFAULT_TARGET),
    range,
    generatedAt: Date.now(),
    timezone: TIME_ZONE,
    nightWindow: '23:00-06:00 Asia/Shanghai',
    latest,
    current: latest ? (latest.ok ? 'up' : 'down') : 'unknown',
    uptime: {
      percent: summary.percent,
      up: summary.up,
      down: summary.down,
      total: summary.total,
      avgLatency: summary.avgLatency,
    },
    days: daysData,
    checks: summary.checks.slice(-6000),
  };
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runCheck(env, { source: 'cron' }).catch(err => {
      console.error('uptime check failed', err);
    }));
  },

  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    if (!env.UPTIME_KV) {
      return json({ error: 'UPTIME_KV binding is missing' }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'GET' && (path === '/' || path === '/health')) {
      return json({
        ok: true,
        service: 'GreenBox uptime monitor',
        timezone: TIME_ZONE,
        nightWindow: '23:00-06:00 Asia/Shanghai',
        endpoints: ['/api/uptime?range=24h', '/api/uptime?range=7d', '/api/latest'],
      });
    }

    if (request.method === 'GET' && path === '/api/latest') {
      const data = await loadRange(env, '24h');
      return json({ ok: true, latest: data.latest, current: data.current, uptime: data.uptime, target: data.target });
    }

    if (request.method === 'GET' && (path === '/api/uptime' || path === '/uptime')) {
      const range = ['24h', '7d', '30d'].includes(url.searchParams.get('range'))
        ? url.searchParams.get('range')
        : '24h';
      const data = await loadRange(env, range);
      return json({ ok: true, ...data });
    }

    if (request.method === 'POST' && path === '/run') {
      const token = request.headers.get('Authorization') || '';
      if (!env.MONITOR_TOKEN || token !== `Bearer ${env.MONITOR_TOKEN}`) {
        return json({ error: 'unauthorized' }, 401);
      }
      const result = await runCheck(env, { force: url.searchParams.get('force') === '1' });
      return json({ ok: true, result });
    }

    return json({ error: 'not found' }, 404);
  },
};
