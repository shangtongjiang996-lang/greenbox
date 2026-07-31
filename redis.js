const Redis = require('ioredis');
const client = new Redis(process.env.REDIS_URL);

// 与 Cloudflare KV 完全相同的接口
async function kvGet(key) {
  const val = await client.get(key);
  if (!val) return null;
  // 尝试解析 JSON（原 Worker 用 'json' 参数）
  try { return JSON.parse(val); } catch { return val; }
}

async function kvPut(key, value, options = {}) {
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (options.expirationTtl) {
    await client.setex(key, options.expirationTtl, str);
  } else {
    await client.set(key, str);
  }
}

async function kvDelete(key) {
  await client.del(key);
}

async function kvList({ prefix }) {
  const keys = await client.keys(`${prefix}*`);
  return { keys: keys.map(k => ({ name: k })) };
}

// 用于增加原子计数（速率限制）
async function kvIncr(key, ttlSeconds) {
  const val = await client.incr(key);
  if (ttlSeconds) await client.expire(key, ttlSeconds);
  return val;
}

module.exports = { kvGet, kvPut, kvDelete, kvList, kvIncr };