const Redis = require('ioredis');
const crypto = require('crypto');
const client = new Redis(process.env.REDIS_URL);
client.on('connect', () => console.log('Redis 连接成功'));
client.on('error', (err) => console.error('Redis 错误:', err));
// 与 Cloudflare KV 完全相同的接口
async function kvGet(key) {
  const val = await client.get(key);
  if (!val) return null;
  // 尝试解析 JSON（原 Worker 用 'json' 参数）
  try { return JSON.parse(val); } catch { return val; }
}

async function kvGetRaw(key) {
  return client.get(key);
}

async function kvPut(key, value, options = {}) {
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (options.expirationTtl) {
    await client.setex(key, options.expirationTtl, str);
  } else {
    await client.set(key, str);
  }
}

async function kvPutRaw(key, value, options = {}) {
  if (options.expirationTtl) {
    await client.setex(key, options.expirationTtl, String(value));
  } else {
    await client.set(key, String(value));
  }
}

async function kvDelete(key) {
  await client.del(key);
}

async function kvScan(pattern = '*', count = 200) {
  let cursor = '0';
  const keys = [];
  do {
    const reply = await client.scan(cursor, 'MATCH', pattern, 'COUNT', count);
    cursor = reply[0];
    if (Array.isArray(reply[1]) && reply[1].length) keys.push(...reply[1]);
  } while (cursor !== '0');
  return keys;
}

async function kvList({ prefix }) {
  const keys = await kvScan(`${prefix}*`);
  return { keys: keys.map(k => ({ name: k })) };
}

// 用于增加原子计数（速率限制）
async function kvIncr(key, ttlSeconds) {
  const val = await client.incr(key);
  if (ttlSeconds) await client.expire(key, ttlSeconds);
  return val;
}

// 基于 Redis 的短锁，保护“读-改-写”不被并发覆盖
async function kvWithLock(key, fn, options = {}) {
  const ttl = options.ttlMs || 5000;
  const attempts = options.attempts || 160;
  const wait = options.waitMs || 25;
  const lockKey = `__lock:${key}`;
  const token = crypto.randomUUID();

  for (let i = 0; i < attempts; i++) {
    const acquired = await client.set(lockKey, token, 'PX', ttl, 'NX');
    if (acquired === 'OK') {
      try {
        return await fn();
      } finally {
        try {
          await client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
            1, lockKey, token
          );
        } catch (e) {}
      }
    }
    await new Promise(resolve => setTimeout(resolve, wait));
  }

  const err = new Error('数据正在被其他请求修改，请稍后重试');
  err.code = 'LOCK_TIMEOUT';
  throw err;
}

async function kvUpdate(key, updater, fallback, options = {}) {
  return kvWithLock(key, async () => {
    const currentValue = await kvGet(key);
    const current = currentValue === null ? fallback : currentValue;
    const next = await updater(current);
    if (next !== undefined) await kvPut(key, next, options);
    return next === undefined ? current : next;
  }, options);
}

async function kvAppend(key, item, cap, options = {}) {
  return kvWithLock(key, async () => {
    const list = (await kvGet(key)) || [];
    const next = Array.isArray(list) ? list.slice() : [];
    next.push(item);
    const trimmed = cap ? next.slice(-cap) : next;
    await kvPut(key, trimmed);
    return trimmed;
  }, options);
}

module.exports = {
  kvGet,
  kvGetRaw,
  kvPut,
  kvPutRaw,
  kvDelete,
  kvScan,
  kvList,
  kvIncr,
  kvWithLock,
  kvUpdate,
  kvAppend,
};