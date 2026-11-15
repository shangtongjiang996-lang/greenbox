'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const BASE = (process.env.BASE_URL || 'https://greenboxhweb.com').replace(/\/$/, '');

async function get(path) {
  const res = await fetch(BASE + path, { redirect: 'follow' });
  return res;
}

async function getJson(path) {
  const res = await get(path);
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { res, data };
}

test('公开页面可以访问', async () => {
  const pages = [
    '/',
    '/tools.html',
    '/changelog.html',
    '/forum.html',
    '/messages.html',
    '/resources.html',
    '/gomoku-online.html',
    '/gomoku-ai.html',
    '/gomoku-rankings.html',
    '/gomoku-replay.html',
    '/gomoku-spectate.html',
    '/notifications.html',
    '/report.html',
    '/feedback.html',
    '/submit-tool.html',
    '/login.html',
    '/register.html',
    '/admin.html',
    '/offline.html'
  ];
  for (const page of pages) {
    const res = await get(page);
    assert.equal(res.status, 200, `${page} 状态码应为 200`);
  }
});

test('PWA 与 SEO 资源可以访问', async () => {
  for (const path of ['/manifest.webmanifest', '/sw.js', '/icon-192.png', '/icon-512.png', '/sitemap.xml', '/robots.txt']) {
    const res = await get(path);
    assert.equal(res.status, 200, `${path} 状态码应为 200`);
  }
  const robots = await (await get('/robots.txt')).text();
  assert.ok(!/Disallow:\s*\/tool\//.test(robots), 'robots.txt 不应屏蔽公开工具页');
});

test('核心 API 正常，权限接口受保护', async () => {
  const data = await getJson('/api/data');
  assert.equal(data.res.status, 200);
  assert.ok(data.data && Array.isArray(data.data.tools));

  const health = await getJson('/api/health');
  assert.equal(health.res.status, 200);
  assert.equal(health.data.ok, true);
  assert.equal(health.data.socketAdapter, true);

  const leaderboard = await getJson('/api/gomoku/leaderboard');
  assert.equal(leaderboard.res.status, 200);
  assert.ok(Array.isArray(leaderboard.data));

  const matches = await getJson('/api/gomoku/matches');
  assert.equal(matches.res.status, 200);
  assert.ok(Array.isArray(matches.data));

  const guards = [
    ['/api/sessions', 401],
    ['/api/notifications/preferences', 401],
    ['/api/push/public-key', 401],
    ['/api/tools/mine', 401],
    ['/api/admin/backup/export', 403],
    ['/api/admin/2fa/status', 403],
    ['/api/admin/reports', 403],
    ['/api/admin/audit-logs', 403]
  ];
  for (const [path, expected] of guards) {
    const res = await get(path);
    assert.equal(res.status, expected, `${path} 应为 ${expected}`);
  }
});

test('公开工具页有分享卡片 meta', async () => {
  const data = await getJson('/api/data');
  const tool = (data.data.tools || []).find(x => x && typeof x.url === 'string' && x.url.startsWith('/tool/'));
  if (!tool) return;
  const html = await (await get(tool.url)).text();
  assert.ok(/property="og:title"/.test(html), '工具页应包含 og:title');
  assert.ok(/property="og:image"/.test(html), '工具页应包含 og:image');
  assert.ok(/application\/ld\+json/.test(html), '工具页应包含结构化数据');
});

test('Sitemap 收录公开工具', async () => {
  const xml = await (await get('/sitemap.xml')).text();
  assert.ok(/<urlset/.test(xml));
  assert.ok(/\/sitemap\.xml/.test(xml) === false);
  assert.ok(/<loc>https:\/\/greenboxhweb\.com\/tools\.html<\/loc>/.test(xml));
  assert.ok(/\/tool\//.test(xml) || /\/usertool\//.test(xml), 'Sitemap 应包含工具页');
});
