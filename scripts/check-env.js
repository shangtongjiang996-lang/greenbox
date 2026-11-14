'use strict';

require('dotenv').config();

const problems = [];
const warnings = [];

function val(name) {
  return String(process.env[name] || '').trim();
}

const redis = val('REDIS_URL');
const zhipu = val('ZHIPU_API_KEY');
const b2KeyId = val('B2_KEY_ID');
const b2AppKey = val('B2_APP_KEY');

if (!redis) {
  problems.push('REDIS_URL 没有设置');
} else {
  try {
    const u = new URL(redis);
    if (!['redis:', 'rediss:'].includes(u.protocol)) {
      problems.push('REDIS_URL 必须以 redis:// 或 rediss:// 开头');
    }
  } catch (e) {
    problems.push('REDIS_URL 不是有效的 URL（当前值不是 Redis 连接串）');
  }
}

if (!zhipu) {
  problems.push('ZHIPU_API_KEY 没有设置');
} else if (zhipu.length < 20) {
  problems.push('ZHIPU_API_KEY 长度异常');
}

if (!b2KeyId) problems.push('B2_KEY_ID 没有设置');
if (!b2AppKey) problems.push('B2_APP_KEY 没有设置');
if (!val('B2_BUCKET_NAME')) problems.push('B2_BUCKET_NAME 没有设置');
if (!val('B2_REGION')) problems.push('B2_REGION 没有设置');

const endpoint = val('B2_ENDPOINT');
if (!endpoint) {
  problems.push('B2_ENDPOINT 没有设置');
} else if (endpoint.includes('://')) {
  problems.push('B2_ENDPOINT 不要带 https://，只填主机名');
}

if (redis && zhipu && redis === zhipu) {
  problems.push('REDIS_URL 和 ZHIPU_API_KEY 的值完全相同，疑似复制错了');
}
if (redis && b2KeyId && redis === b2KeyId) {
  problems.push('REDIS_URL 和 B2_KEY_ID 的值完全相同，疑似复制错了');
}
if (redis && b2AppKey && redis === b2AppKey) {
  problems.push('REDIS_URL 和 B2_APP_KEY 的值完全相同，疑似复制错了');
}
if (zhipu && b2KeyId && zhipu === b2KeyId) {
  problems.push('ZHIPU_API_KEY 和 B2_KEY_ID 的值完全相同，疑似复制错了');
}
if (zhipu && b2AppKey && zhipu === b2AppKey) {
  problems.push('ZHIPU_API_KEY 和 B2_APP_KEY 的值完全相同，疑似复制错了');
}

if (zhipu.startsWith('ibsec_')) {
  warnings.push('ZHIPU_API_KEY 是 InstaBox 代理占位符；只有配置了对应 Secret 的允许主机时才能工作');
}
if (!val('ADMIN')) {
  warnings.push('ADMIN 未设置；如果 Redis 中没有管理员密码，后台将无法初始化登录密码');
}

for (const w of warnings) console.warn('WARN:', w);

if (problems.length) {
  console.error('环境变量检查未通过：');
  for (const p of problems) console.error('-', p);
  process.exit(1);
}

console.log('环境变量检查通过');
