require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const crypto = require('crypto');
const { kvGet, kvPut, kvDelete, kvList, kvIncr } = require('./redis');

// ===== 社交模块 =====
const { registerSocialRoutes, registerSocialSocket, emitToUser } = require('./social');

// ===== B2 对象存储 SDK =====
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: 50 * 1024 * 1024 } // 限制最大 50MB，防止撑爆 Render 内存
});

// ======== 辅助函数 ========
const SESSION_TTL = 7 * 24 * 60 * 60;
const RESERVED_USERNAMES = ['admin','administrator','root','system','__proto__','constructor','prototype'];
const USERNAME_RE = /^[a-zA-Z0-9_\u4e00-\u9fa5]{3,20}$/;

function isValidUsername(u) { return typeof u === 'string' && USERNAME_RE.test(u) && !RESERVED_USERNAMES.includes(u.toLowerCase()); }
function isValidPassword(p) { return typeof p === 'string' && p.length >= 6 && p.length <= 72; }
function toHex(buffer) { return Array.from(new Uint8Array(buffer)).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function clientIp(req) { return req.headers['cf-connecting-ip'] || req.ip || 'unknown'; }

async function hashPasswordPBKDF2(password, saltHex, iterations) {
  const salt = Buffer.from(saltHex, 'hex');
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, 32, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex'));
    });
  });
}

async function createUserRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 100000;
  const passwordHash = await hashPasswordPBKDF2(password, salt, iterations);
  return { passwordHash, salt, iterations, algo: 'pbkdf2-sha256', role: 'user', createdAt: Date.now() };
}

async function verifyUserRecord(user, password) {
  if (user.algo === 'pbkdf2-sha256' && user.iterations) {
    const candidate = await hashPasswordPBKDF2(password, user.salt, user.iterations);
    if (candidate === user.passwordHash) return { ok: true, needsUpgrade: false };
    return { ok: false };
  }
  const hash = crypto.createHash('sha256').update(password + user.salt).digest('hex');
  if (hash !== user.passwordHash) return { ok: false };
  const upgraded = await createUserRecord(password);
  upgraded.role = user.role || 'user';
  return { ok: true, needsUpgrade: true, upgradedRecord: upgraded };
}

function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) throw new Error('ENCRYPTION_KEY 未配置');
  return crypto.createHash('sha256').update(key).digest();
}

function encryptPassword(plain) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), data: encrypted.toString('hex') };
}

function decryptPassword(encObj) {
  const key = getEncryptionKey();
  const iv = Buffer.from(encObj.iv, 'hex');
  const encrypted = Buffer.from(encObj.data, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

async function getSession(token) {
  if (!token) return null;
  const session = await kvGet(`session:${token}`);
  if (!session) return null;
  if (session.expires && session.expires < Date.now()) {
    await kvDelete(`session:${token}`);
    return null;
  }
  return session;
}

async function createSession(username, role) {
  const token = crypto.randomUUID() + Date.now().toString(36);
  const expires = Date.now() + SESSION_TTL * 1000;
  await kvPut(`session:${token}`, { username, role, expires }, { expirationTtl: SESSION_TTL });
  return token;
}

function getBearerToken(req) {
  const auth = req.headers.authorization;
  return auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

async function checkAdmin(req) {
  const token = getBearerToken(req);
  const session = await getSession(token);
  return !!(session && session.role === 'admin');
}

async function checkRateLimit(key, limit, windowSeconds) {
  const count = await kvIncr(key, windowSeconds);
  return count <= limit;
}

async function getPublicProfile(username) {
  const profile = await kvGet(`user_profile:${username}`) || {};
  const avatar = await kvGet(`user_avatar:${username}`);
  let role = 'user';
  if (username === 'admin') role = 'admin';
  else {
    const users = await kvGet('users') || {};
    role = (users[username] && users[username].role) || 'user';
  }
  return {
    username,
    displayName: profile.displayName || (username === 'admin' ? '管理员' : username),
    bio: profile.bio || '',
    role,
    hasAvatar: !!avatar,
    updatedAt: profile.updatedAt || null,
  };
}

// ===== B2 存储客户端初始化（修复 CORS 与崩溃问题） =====
const b2Client = new S3Client({
  region: process.env.B2_REGION || 'us-east-005',
  endpoint: `https://${process.env.B2_ENDPOINT}`,
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.B2_KEY_ID,
    secretAccessKey: process.env.B2_APP_KEY,
  },
});

const MONTHLY_LIMIT = 2.5 * 1024 * 1024 * 1024; // 2.5 GB

function getCurrentMonth() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

// ======== REST API ========
app.post('/api/register', async (req, res) => {
  const ip = clientIp(req);
  if (!(await checkRateLimit(`rl:register:${ip}`, 5, 3600))) return res.status(429).json({ error: '请求过于频繁' });
  const { username, password } = req.body;
  if (!isValidUsername(username)) return res.status(400).json({ error: '用户名格式错误' });
  if (!isValidPassword(password)) return res.status(400).json({ error: '密码长度需6-72位' });
  const users = await kvGet('users') || {};
  if (users[username]) return res.status(409).json({ error: '用户名已存在' });
  const record = await createUserRecord(password);
  record.encryptedPassword = encryptPassword(password);
  users[username] = record;
  await kvPut('users', users);
  res.json({ success: true, message: '注册成功' });
});

app.post('/api/login', async (req, res) => {
  const ip = clientIp(req);
  if (!(await checkRateLimit(`rl:login:${ip}`, 10, 600))) return res.status(429).json({ error: '登录过于频繁' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  
  if (username === 'admin') {
    let adminPwd = await kvGet('admin_password') || process.env.ADMIN;
    if (!adminPwd) return res.status(503).json({ error: '管理员未配置' });
    if (password !== adminPwd) return res.status(401).json({ error: '用户名或密码错误' });
    const token = await createSession('admin', 'admin');
    return res.json({ success: true, token, username: 'admin', role: 'admin', needsUpgrade: false });
  }
  
  const users = await kvGet('users') || {};
  const user = users[username];
  if (!user) return res.status(401).json({ error: '用户名或密码错误' });
  const result = await verifyUserRecord(user, password);
  if (!result.ok) return res.status(401).json({ error: '用户名或密码错误' });
  
  if (result.needsUpgrade) {
    const upgraded = result.upgradedRecord;
    upgraded.encryptedPassword = user.encryptedPassword || encryptPassword(password);
    users[username] = upgraded;
    await kvPut('users', users);
  }
  const token = await createSession(username, user.role || 'user');
  const needsUpgrade = !user.encryptedPassword || user.algo !== 'pbkdf2-sha256';
  res.json({ success: true, token, username, role: user.role || 'user', needsUpgrade });
});

app.get('/api/verify', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ valid: false });

  const profile = await getPublicProfile(session.username);

  let needsUpgrade = false;
  if (session.username !== 'admin') {
    const users = await kvGet('users') || {};
    const user = users[session.username];
    needsUpgrade = !!(user && (!user.encryptedPassword || user.algo !== 'pbkdf2-sha256'));
  }

  res.json({
    valid: true,
    username: session.username,
    role: session.role,
    needsUpgrade,
    displayName: profile.displayName,
    bio: profile.bio,
    hasAvatar: profile.hasAvatar,
  });
});

app.post('/api/logout', async (req, res) => {
  const token = getBearerToken(req);
  if (token) await kvDelete(`session:${token}`);
  res.json({ success: true });
});

app.post('/api/change-my-password', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  if (session.username === 'admin') return res.status(403).json({ error: '请使用管理后台修改密码' });
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: '密码至少6位' });
  const users = await kvGet('users') || {};
  const user = users[session.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const newRecord = await createUserRecord(newPassword);
  newRecord.role = user.role || 'user';
  newRecord.encryptedPassword = encryptPassword(newPassword);
  newRecord.createdAt = user.createdAt || Date.now();
  users[session.username] = newRecord;
  await kvPut('users', users);
  res.json({ success: true });
});

app.post('/api/delete-account', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  if (session.username === 'admin') return res.status(403).json({ error: '不能删除管理员' });
  const users = await kvGet('users') || {};
  delete users[session.username];
  await kvPut('users', users);
  await kvDelete(`session:${token}`);
  await kvDelete(`user_profile:${session.username}`);
  await kvDelete(`user_avatar:${session.username}`);
  await kvDelete(`notif_read:${session.username}`);
  await kvDelete(`notif_deleted:${session.username}`);
  await kvDelete(`chat_sessions:${session.username}`);
  await kvDelete(`chat_limit:${session.username}`);
  
  await kvDelete(`user_settings:${session.username}`);
  await kvDelete(`friends:${session.username}`);
  await kvDelete(`friend_requests:${session.username}`);
  await kvDelete(`friend_requests_out:${session.username}`);
  await kvDelete(`dm_convos:${session.username}`);
  
  try {
    const { removeUserFromAllFriends } = require('./social');
    await removeUserFromAllFriends(session.username);
  } catch (e) {}
  res.json({ success: true });
});
// ======== 用户资料 API ========
app.get('/api/user/profile/:username', async (req, res) => {
  const username = req.params.username;
  if (!username) return res.status(400).json({ error: '缺少用户名' });
  const users = await kvGet('users') || {};
  if (username !== 'admin' && !users[username]) {
    return res.status(404).json({ error: '用户不存在' });
  }
  const profile = await getPublicProfile(username);
  res.json(profile);
});

app.get('/api/user/me', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const profile = await getPublicProfile(session.username);
  res.json(profile);
});

app.put('/api/user/profile', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const { displayName, bio } = req.body || {};
  const profile = await kvGet(`user_profile:${session.username}`) || {};

  if (typeof displayName === 'string') {
    const dn = displayName.trim().slice(0, 20);
    if (dn) profile.displayName = dn;
    else delete profile.displayName;
  }
  if (typeof bio === 'string') {
    profile.bio = bio.trim().slice(0, 100);
  }
  profile.updatedAt = Date.now();

  await kvPut(`user_profile:${session.username}`, profile);
  res.json({ success: true, profile });
});

app.post('/api/user/avatar', upload.single('avatar'), async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const file = req.file;
  if (!file) return res.status(400).json({ error: '请选择图片文件' });
  if (!/^image\/(jpeg|jpg|png|gif|webp)$/i.test(file.mimetype)) {
    return res.status(400).json({ error: '仅支持 JPG/PNG/GIF/WEBP 格式' });
  }
  if (file.size > 500 * 1024) {
    return res.status(400).json({ error: '图片不能超过 500KB' });
  }

  const base64 = file.buffer.toString('base64');
  const dataUri = `data:${file.mimetype};base64,${base64}`;
  await kvPut(`user_avatar:${session.username}`, dataUri);
  res.json({ success: true });
});

app.get('/api/user/avatar/:username', async (req, res) => {
  const username = req.params.username;
  const avatar = await kvGet(`user_avatar:${username}`);
  if (!avatar || typeof avatar !== 'string') return res.status(404).send('无头像');

  const match = avatar.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) return res.status(500).send('头像格式错误');

  const mime = match[1];
  const buf = Buffer.from(match[2], 'base64');
  res.set('Content-Type', mime);
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(buf);
});

app.delete('/api/user/avatar', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  await kvDelete(`user_avatar:${session.username}`);
  res.json({ success: true });
});

// ======== 站点数据 ========
app.get('/api/data', async (req, res) => {
  const data = await kvGet('site_data') || { tools: [], changelogs: [] };
  res.json(data);
});

app.post('/api/update', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const clean = req.body;
  await kvPut('site_data', clean);
  res.json({ success: true });
});

app.post('/api/tool/upload', upload.single('file'), async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { name, icon, description, category } = req.body;
  const file = req.file;
  if (!file || !file.originalname.toLowerCase().endsWith('.html')) {
    return res.status(400).json({ error: '请上传 .html 文件' });
  }
  const htmlContent = file.buffer.toString('utf8');
  if (!htmlContent.trim()) return res.status(400).json({ error: '文件内容为空' });
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  await kvPut(`tool_content:${id}`, htmlContent);
  const currentData = (await kvGet('site_data')) || { tools: [], changelogs: [] };
  currentData.tools.push({ name, icon, description, category, url: `/tool/${id}` });
  await kvPut('site_data', currentData);
  res.json({ success: true, id, url: `/tool/${id}` });
});

app.get('/tool/:id', async (req, res) => {
  const html = await kvGet(`tool_content:${req.params.id}`);
  if (!html) return res.status(404).send('工具不存在');
  res.set('Content-Type', 'text/html; charset=utf-8').send(html);
});

// ======== 资源中心 (B2 上传与配额) ========
// 生成预签名上传链接（前端直传 B2）
app.post('/api/resource/upload-url', async (req, res) => {
  const session = await getSession(getBearerToken(req));
  if (!session) return res.status(401).json({ error: '请先登录' });

  const { filename, contentType, fileSize } = req.body;
  if (!filename || !contentType || !fileSize) {
    return res.status(400).json({ error: '缺少文件信息' });
  }
  if (fileSize > MONTHLY_LIMIT) {
    return res.status(400).json({ error: '单个文件不能超过 2GB' });
  }

  // 配额检查
  if (session.role !== 'admin') {
    const quotaKey = `upload_quota:${session.username}:${getCurrentMonth()}`;
    const used = parseInt(await kvGet(quotaKey) || '0', 10);
    if (used + fileSize > MONTHLY_LIMIT) {
      return res.status(429).json({ error: `本月额度不足，剩余 ${((MONTHLY_LIMIT - used) / 1024 / 1024).toFixed(1)} MB` });
    }
  }

  const ext = filename.split('.').pop();
  const objectKey = `resources/${session.username}/${crypto.randomUUID()}.${ext}`;

  // 生成直传命令
  const command = new PutObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: objectKey,
    ContentType: contentType,
  });

  // 生成 B2 直传链接（1小时有效）
  const uploadUrl = await getSignedUrl(b2Client, command, { expiresIn: 3600 });
  
  // 因为改用前端直传，原 /api/resource/confirm 接口依然保留，前端传完后再调它保存记录
  res.json({ uploadUrl, objectKey });
});
app.post('/api/resource/confirm', async (req, res) => {
  const session = await getSession(getBearerToken(req));
  if (!session) return res.status(401).json({ error: '请先登录' });

  const { objectKey, fileSize, title, category } = req.body;
  if (!objectKey || !fileSize) return res.status(400).json({ error: '参数缺失' });

  // 扣除配额
  if (session.role !== 'admin') {
    const quotaKey = `upload_quota:${session.username}:${getCurrentMonth()}`;
    const used = parseInt(await kvGet(quotaKey) || '0', 10);
    await kvPut(quotaKey, used + fileSize, { expirationTtl: 62 * 24 * 3600 });
  }

  // 生成播放链接（7天有效）
  const getCommand = new GetObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: objectKey,
  });
  const playUrl = await getSignedUrl(b2Client, getCommand, { expiresIn: 7 * 24 * 3600 });

  const resourceId = 'res_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
  const record = {
    id: resourceId,
    objectKey,
    playUrl,
    title: String(title || '未命名资源').slice(0, 100),
    category: ['movie', 'music', 'software', 'other'].includes(category) ? category : 'other',
    fileSize,
    uploader: session.username,
    createdAt: Date.now(),
  };
  
  await kvPut(`resource:${resourceId}`, record);

  const indexKey = `resource_index:${record.category}`;
  const index = (await kvGet(indexKey)) || [];
  index.unshift(resourceId);
  await kvPut(indexKey, index.slice(0, 500));

  res.json({ success: true, resourceId, playUrl });
});

app.get('/api/resource/quota', async (req, res) => {
  const session = await getSession(getBearerToken(req));
  if (!session) return res.status(401).json({ error: '请先登录' });

  if (session.role === 'admin') {
    return res.json({ unlimited: true, used: 0, limit: -1 });
  }

  const quotaKey = `upload_quota:${session.username}:${getCurrentMonth()}`;
  const used = parseInt(await kvGet(quotaKey) || '0', 10);
  res.json({
    unlimited: false,
    used,
    limit: MONTHLY_LIMIT,
    remaining: Math.max(0, MONTHLY_LIMIT - used),
  });
});

app.get('/api/resource/list/:category', async (req, res) => {
  const category = req.params.category;
  const indexKey = `resource_index:${category}`;
  const ids = (await kvGet(indexKey)) || [];
  
  const list = [];
  for (const id of ids.slice(0, 50)) {
    const item = await kvGet(`resource:${id}`);
    if (item) list.push(item);
  }
  res.json(list);
});


// ============================================================
//  AI 聊天助手
// ============================================================
const CHAT_DEFAULT_LIMIT = 20;
const ZHIPU_API_URL = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';

const DEFAULT_CHAT_CONFIG = {
  model: 'glm-4-flash',
  temperature: 0.7,
  maxTokens: 2000,
  systemPrompt: '你是 GreenBox 网站的 AI 助手，回答简洁、友好、准确。涉及本站工具（如五子棋、PDF合并器）时可主动介绍。',
  welcomeMessage: '你好！我是 GreenBox 的 AI 助手 ✨\n有什么可以帮你的吗？',
  presetQuestions: [
    '介绍一下 GreenBox 有哪些工具',
    '五子棋怎么玩？',
    '你能帮我写代码吗？',
    '今天有什么热门新闻？'
  ],
  quickPhrases: [
    '继续',
    '换个说法',
    '再详细一点',
    '举个例子',
    '总结一下'
  ],
  enableDeepThink: true,
  enableHistory: true,
  enableBrowserInfo: true,
  browserInfoTemplate: '【环境信息】\n时间：{time}\n时区：{timezone}\n语言：{lang}\n屏幕：{screen}\n网络：{network}',
  deepThinkPrompt: '在回答用户问题前，请先在 [THOUGHT] 和 [/THOUGHT] 标签内进行深度思考（分析问题、列举方案、评估优缺点），然后在 [ANSWER] 和 [/ANSWER] 标签内给出最终答案。'
};

function todayKey() {
  const now = new Date();
  const bj = new Date(now.getTime() + 8 * 3600 * 1000);
  return bj.toISOString().slice(0, 10);
}

async function getChatConfig() {
  const cfg = await kvGet('chat_config');
  if (!cfg || typeof cfg !== 'object') return { ...DEFAULT_CHAT_CONFIG };
  return { ...DEFAULT_CHAT_CONFIG, ...cfg };
}

async function getUserChatLimit(username) {
  let limit = await kvGet(`chat_limit:${username}`);
  if (limit === null || limit === undefined) {
    limit = await kvGet('chat_limit:default');
    if (limit === null || limit === undefined) limit = CHAT_DEFAULT_LIMIT;
  }
  const n = parseInt(limit, 10);
  return isNaN(n) ? CHAT_DEFAULT_LIMIT : n;
}

async function getUsedToday(username) {
  const raw = await kvGet(`chat_quota:${username}:${todayKey()}`);
  return raw ? parseInt(raw, 10) : 0;
}

async function consumeQuota(username) {
  const key = `chat_quota:${username}:${todayKey()}`;
  const used = await getUsedToday(username);
  const newUsed = used + 1;
  await kvPut(key, newUsed, { expirationTtl: 60 * 60 * 48 });
  return newUsed;
}

async function getUserSessions(username) {
  const list = await kvGet(`chat_sessions:${username}`);
  return Array.isArray(list) ? list : [];
}

async function saveUserSessions(username, list) {
  await kvPut(`chat_sessions:${username}`, list.slice(0, 50));
}

function genSessionId() {
  return 'S' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function genTitle(text) {
  const t = String(text).replace(/\s+/g, ' ').trim();
  return t.length > 20 ? t.slice(0, 20) + '...' : t || '新对话';
}

app.get('/api/chat/config', async (req, res) => {
  const cfg = await getChatConfig();
  res.json({
    welcomeMessage: cfg.welcomeMessage,
    presetQuestions: cfg.presetQuestions,
    quickPhrases: cfg.quickPhrases,
    enableDeepThink: cfg.enableDeepThink,
    enableHistory: cfg.enableHistory,
    model: cfg.model,
  });
});

app.get('/api/chat/quota', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  if (session.role === 'admin') {
    return res.json({ limit: -1, used: 0, remaining: -1, unlimited: true });
  }
  const limit = await getUserChatLimit(session.username);
  const used = await getUsedToday(session.username);
  res.json({ limit, used, remaining: Math.max(0, limit - used) });
});

app.get('/api/chat/sessions', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const cfg = await getChatConfig();
  if (!cfg.enableHistory) return res.json([]);
  const list = await getUserSessions(session.username);
  res.json(list);
});

app.post('/api/chat/sessions', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const cfg = await getChatConfig();
  if (!cfg.enableHistory) return res.status(403).json({ error: '历史功能已关闭' });

  const sid = genSessionId();
  const now = Date.now();
  const newSession = {
    id: sid,
    title: '新对话',
    createdAt: now,
    updatedAt: now,
    messages: [],
  };

  const list = await getUserSessions(session.username);
  list.unshift({ id: sid, title: newSession.title, createdAt: now, updatedAt: now, count: 0 });
  await saveUserSessions(session.username, list);
  await kvPut(`chat_session:${session.username}:${sid}`, newSession, { expirationTtl: 30 * 24 * 3600 });

  res.json({ success: true, session: newSession });
});

app.get('/api/chat/sessions/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const cfg = await getChatConfig();
  if (!cfg.enableHistory) return res.status(403).json({ error: '历史功能已关闭' });

  const data = await kvGet(`chat_session:${session.username}:${req.params.id}`);
  if (!data) return res.status(404).json({ error: '会话不存在' });
  res.json(data);
});

app.put('/api/chat/sessions/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const cfg = await getChatConfig();
  if (!cfg.enableHistory) return res.status(403).json({ error: '历史功能已关闭' });

  const sid = req.params.id;
  const data = await kvGet(`chat_session:${session.username}:${sid}`);
  if (!data) return res.status(404).json({ error: '会话不存在' });

  const { title, messages } = req.body || {};
  if (typeof title === 'string' && title.trim()) data.title = title.trim().slice(0, 50);
  if (Array.isArray(messages)) {
    data.messages = messages.slice(-100).map(m => ({
      role: ['user', 'assistant', 'system'].includes(m.role) ? m.role : 'user',
      content: String(m.content || '').slice(0, 8000),
      time: m.time || Date.now(),
      thought: m.thought ? String(m.thought).slice(0, 4000) : undefined,
    }));
  }
  data.updatedAt = Date.now();
  await kvPut(`chat_session:${session.username}:${sid}`, data, { expirationTtl: 30 * 24 * 3600 });

  const list = await getUserSessions(session.username);
  const idx = list.findIndex(s => s.id === sid);
  if (idx >= 0) {
    list[idx].title = data.title;
    list[idx].updatedAt = data.updatedAt;
    list[idx].count = data.messages.length;
    const [item] = list.splice(idx, 1);
    list.unshift(item);
    await saveUserSessions(session.username, list);
  }
  res.json({ success: true });
});

app.delete('/api/chat/sessions/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const sid = req.params.id;
  await kvDelete(`chat_session:${session.username}:${sid}`);
  const list = await getUserSessions(session.username);
  const newList = list.filter(s => s.id !== sid);
  await saveUserSessions(session.username, newList);
  res.json({ success: true });
});

app.post('/api/chat/stream', async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = await getSession(token);
    if (!session) return res.status(401).json({ error: '请先登录后使用' });

    const username = session.username;
    const isAdmin = session.role === 'admin';
    const cfg = await getChatConfig();
    const limit = isAdmin ? -1 : await getUserChatLimit(username);
    const used = isAdmin ? 0 : await getUsedToday(username);

    if (!isAdmin) {
      if (limit <= 0) return res.status(403).json({ error: 'AI 助手暂未开放' });
      if (used >= limit) {
        return res.status(429).json({ error: `今日对话次数已用完（${limit} 次/天），明天再来吧～` });
      }
    }

    let { messages, sessionId, deepThink, browserInfo } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: '消息不能为空' });
    }

    messages = messages.slice(-20).map(m => ({
      role: ['system', 'user', 'assistant'].includes(m.role) ? m.role : 'user',
      content: String(m.content || '').slice(0, 4000),
    })).filter(m => m.content);

    if (messages.length === 0) return res.status(400).json({ error: '消息内容为空' });

    let sysPrompt = cfg.systemPrompt || DEFAULT_CHAT_CONFIG.systemPrompt;

    if (cfg.enableBrowserInfo && browserInfo && typeof browserInfo === 'object') {
      const tpl = cfg.browserInfoTemplate || DEFAULT_CHAT_CONFIG.browserInfoTemplate;
      const info = tpl
        .replace('{time}', String(browserInfo.time || '').slice(0, 50))
        .replace('{timezone}', String(browserInfo.timezone || '').slice(0, 50))
        .replace('{lang}', String(browserInfo.lang || '').slice(0, 20))
        .replace('{screen}', String(browserInfo.screen || '').slice(0, 30))
        .replace('{network}', String(browserInfo.network || '').slice(0, 30));
      sysPrompt += '\n\n' + info;
    }

    if (deepThink && cfg.enableDeepThink) {
      sysPrompt += '\n\n' + (cfg.deepThinkPrompt || DEFAULT_CHAT_CONFIG.deepThinkPrompt);
    }

    messages.unshift({ role: 'system', content: sysPrompt });

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') res.flushHeaders();

    const apiKey = process.env.ZHIPU_API_KEY || '7b77f8d932f243ce99525a7f4194d755.QJNWfoQtfjyVQCLi';

    let zhipuRes;
    try {
      zhipuRes = await fetch(ZHIPU_API_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: cfg.model || DEFAULT_CHAT_CONFIG.model,
          messages,
          temperature: typeof cfg.temperature === 'number' ? cfg.temperature : 0.7,
          max_tokens: cfg.maxTokens || 2000,
          stream: true,
        }),
      });
    } catch (e) {
      console.error('Zhipu fetch error:', e);
      res.write(`data: ${JSON.stringify({ error: 'AI 服务连接失败' })}\n\n`);
      res.end();
      return;
    }

    if (!zhipuRes.ok) {
      const errText = await zhipuRes.text().catch(() => '');
      console.error('Zhipu API error:', zhipuRes.status, errText);
      let msg = 'AI 服务暂时不可用';
      if (zhipuRes.status === 401) msg = 'AI 服务配置错误';
      if (zhipuRes.status === 429) msg = 'AI 服务繁忙，请稍后再试';
      res.write(`data: ${JSON.stringify({ error: msg })}\n\n`);
      res.end();
      return;
    }

    const reader = zhipuRes.body.getReader();
    const decoder = new TextDecoder();
    let fullResponse = '';
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data:')) continue;
          const data = trimmed.slice(5).trim();
          if (data === '[DONE]') continue;
          try {
            const json = JSON.parse(data);
            const content = json.choices?.[0]?.delta?.content || '';
            if (content) {
              fullResponse += content;
              res.write(`data: ${JSON.stringify({ content })}\n\n`);
            }
          } catch (e) {}
        }
      }
    } catch (streamErr) {
      console.error('Stream error:', streamErr);
    }

    let newUsed = 0;
    if (!isAdmin) {
      newUsed = await consumeQuota(username);
    }

    if (sessionId && cfg.enableHistory) {
      try {
        const data = await kvGet(`chat_session:${username}:${sessionId}`);
        if (data) {
          const userMsg = messages[messages.length - 1];
          if (userMsg && userMsg.role === 'user') {
            let thought = '';
            let answer = fullResponse;
            const thoughtMatch = fullResponse.match(/\[THOUGHT\]([\s\S]*?)\[\/THOUGHT\]/);
            const answerMatch = fullResponse.match(/\[ANSWER\]([\s\S]*?)(\[\/ANSWER\]|$)/);
            if (thoughtMatch) thought = thoughtMatch[1].trim();
            if (answerMatch) answer = answerMatch[1].trim();

            if (!data.messages) data.messages = [];
            data.messages.push({ role: 'user', content: userMsg.content, time: Date.now() });
            data.messages.push({
              role: 'assistant',
              content: answer,
              thought: thought || undefined,
              time: Date.now(),
            });
            data.messages = data.messages.slice(-100);

            if (data.title === '新对话' && data.messages.length <= 2) {
              data.title = genTitle(userMsg.content);
            }
            data.updatedAt = Date.now();
            await kvPut(`chat_session:${username}:${sessionId}`, data, { expirationTtl: 30 * 24 * 3600 });

            const list = await getUserSessions(username);
            const idx = list.findIndex(s => s.id === sessionId);
            if (idx >= 0) {
              list[idx].title = data.title;
              list[idx].updatedAt = data.updatedAt;
              list[idx].count = data.messages.length;
              const [item] = list.splice(idx, 1);
              list.unshift(item);
              await saveUserSessions(username, list);
            }
          }
        }
      } catch (e) {
        console.error('Save session error:', e);
      }
    }

    res.write(`data: ${JSON.stringify({
      done: true,
      reply: fullResponse,
      used: newUsed,
      limit: isAdmin ? -1 : limit,
      remaining: isAdmin ? -1 : Math.max(0, limit - newUsed),
      unlimited: isAdmin,
    })}\n\n`);
    res.end();

  } catch (err) {
    console.error('/api/chat/stream error:', err);
    try {
      res.write(`data: ${JSON.stringify({ error: '服务器内部错误' })}\n\n`);
      res.end();
    } catch (e) {}
  }
});

app.get('/api/admin/chat/config', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const cfg = await getChatConfig();
  res.json(cfg);
});

app.put('/api/admin/chat/config', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const body = req.body || {};
  const old = await getChatConfig();
  const newCfg = { ...old };

  if (typeof body.systemPrompt === 'string') newCfg.systemPrompt = body.systemPrompt.slice(0, 4000);
  if (typeof body.welcomeMessage === 'string') newCfg.welcomeMessage = body.welcomeMessage.slice(0, 500);
  if (Array.isArray(body.presetQuestions)) {
    newCfg.presetQuestions = body.presetQuestions.slice(0, 10).map(s => String(s).slice(0, 100));
  }
  if (Array.isArray(body.quickPhrases)) {
    newCfg.quickPhrases = body.quickPhrases.slice(0, 10).map(s => String(s).slice(0, 50));
  }
  if (typeof body.model === 'string') newCfg.model = body.model.slice(0, 50);
  if (typeof body.temperature === 'number' && body.temperature >= 0 && body.temperature <= 1) {
    newCfg.temperature = body.temperature;
  }
  if (typeof body.maxTokens === 'number' && body.maxTokens > 0 && body.maxTokens <= 8000) {
    newCfg.maxTokens = body.maxTokens;
  }
  if (typeof body.enableDeepThink === 'boolean') newCfg.enableDeepThink = body.enableDeepThink;
  if (typeof body.enableHistory === 'boolean') newCfg.enableHistory = body.enableHistory;
  if (typeof body.enableBrowserInfo === 'boolean') newCfg.enableBrowserInfo = body.enableBrowserInfo;
  if (typeof body.browserInfoTemplate === 'string') newCfg.browserInfoTemplate = body.browserInfoTemplate.slice(0, 1000);
  if (typeof body.deepThinkPrompt === 'string') newCfg.deepThinkPrompt = body.deepThinkPrompt.slice(0, 1000);

  await kvPut('chat_config', newCfg);
  res.json({ success: true, config: newCfg });
});

app.get('/api/admin/chat/limits', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });

  let defaultLimit = await kvGet('chat_limit:default');
  if (defaultLimit === null || defaultLimit === undefined) defaultLimit = CHAT_DEFAULT_LIMIT;

  const users = (await kvGet('users')) || {};
  const userList = Object.keys(users).filter(u => u !== 'admin');

  const limitKeys = await kvList({ prefix: 'chat_limit:' });
  const overrides = {};
  for (const k of limitKeys.keys) {
    if (k.name === 'chat_limit:default') continue;
    const uname = k.name.replace('chat_limit:', '');
    overrides[uname] = await kvGet(k.name);
  }

  const today = todayKey();
  const usage = {};
  const quotaKeys = await kvList({ prefix: 'chat_quota:' });
  for (const k of quotaKeys.keys) {
    if (!k.name.endsWith(`:${today}`)) continue;
    const parts = k.name.split(':');
    if (parts.length < 3) continue;
    const uname = parts[1];
    const val = await kvGet(k.name);
    usage[uname] = parseInt(val, 10) || 0;
  }

  const list = userList.map(u => {
    const hasOverride = overrides[u] !== undefined && overrides[u] !== null;
    const effLimit = hasOverride ? parseInt(overrides[u], 10) : parseInt(defaultLimit, 10);
    return {
      username: u,
      limit: isNaN(effLimit) ? CHAT_DEFAULT_LIMIT : effLimit,
      used: usage[u] || 0,
      hasOverride,
    };
  });

  res.json({
    default: parseInt(defaultLimit, 10) || CHAT_DEFAULT_LIMIT,
    users: list,
  });
});

app.put('/api/admin/chat/limit', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { username, limit } = req.body || {};
  const n = parseInt(limit, 10);
  if (isNaN(n) || n < 0 || n > 10000) return res.status(400).json({ error: '限额需为 0-10000 的整数' });

  if (!username || username === 'default') {
    await kvPut('chat_limit:default', n);
    return res.json({ success: true, message: `默认限额已设为 ${n} 次/天` });
  }

  const users = (await kvGet('users')) || {};
  if (!users[username]) return res.status(404).json({ error: '用户不存在' });

  await kvPut(`chat_limit:${username}`, n);
  res.json({ success: true, message: `${username} 限额已设为 ${n} 次/天` });
});

app.delete('/api/admin/chat/limit/:username', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const username = req.params.username;
  if (!username || username === 'default') return res.status(400).json({ error: '无效用户名' });
  await kvDelete(`chat_limit:${username}`);
  res.json({ success: true, message: `${username} 已恢复默认限额` });
});

app.post('/api/admin/chat/reset-usage', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: '缺少用户名' });
  await kvDelete(`chat_quota:${username}:${todayKey()}`);
  res.json({ success: true });
});
// ============================================================
//  通知系统
// ============================================================
function genNotifId() {
  return 'N' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

async function getUserNotifications(username) {
  const all = (await kvGet('notifications')) || [];
  const readList = (await kvGet(`notif_read:${username}`)) || [];
  const deletedList = (await kvGet(`notif_deleted:${username}`)) || [];
  const readSet = new Set(readList);
  const deletedSet = new Set(deletedList);

  return all
    .filter(n => {
      if (n.target !== 'all' && n.target !== username) return false;
      if (deletedSet.has(n.id)) return false;
      return true;
    })
    .map(n => ({
      id: n.id,
      title: n.title,
      content: n.content,
      type: n.type || 'info',
      createdAt: n.createdAt,
      sender: n.sender || 'admin',
      read: readSet.has(n.id),
    }))
    .sort((a, b) => b.createdAt - a.createdAt);
}

app.get('/api/notifications', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const list = await getUserNotifications(session.username);
  res.json(list);
});

app.get('/api/notifications/unread-count', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const list = await getUserNotifications(session.username);
  const unread = list.filter(n => !n.read).length;
  res.json({ count: unread });
});

app.post('/api/notifications/read', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { ids } = req.body || {};
  const readList = (await kvGet(`notif_read:${session.username}`)) || [];
  const set = new Set(readList);
  if (Array.isArray(ids)) {
    ids.forEach(id => set.add(String(id)));
  } else if (typeof ids === 'string') {
    set.add(ids);
  }
  await kvPut(`notif_read:${session.username}`, Array.from(set).slice(-500));
  res.json({ success: true });
});

app.post('/api/notifications/read-all', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const list = await getUserNotifications(session.username);
  const readList = (await kvGet(`notif_read:${session.username}`)) || [];
  const set = new Set(readList);
  list.forEach(n => set.add(n.id));
  await kvPut(`notif_read:${session.username}`, Array.from(set).slice(-500));
  res.json({ success: true });
});

app.delete('/api/notifications/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const id = req.params.id;
  const deletedList = (await kvGet(`notif_deleted:${session.username}`)) || [];
  const set = new Set(deletedList);
  set.add(id);
  await kvPut(`notif_deleted:${session.username}`, Array.from(set).slice(-500));
  res.json({ success: true });
});

app.delete('/api/notifications', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const list = await getUserNotifications(session.username);
  const deletedList = (await kvGet(`notif_deleted:${session.username}`)) || [];
  const set = new Set(deletedList);
  list.forEach(n => set.add(n.id));
  await kvPut(`notif_deleted:${session.username}`, Array.from(set).slice(-500));
  res.json({ success: true });
});

app.get('/api/admin/notifications', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const list = (await kvGet('notifications')) || [];
  res.json(list.slice().sort((a, b) => b.createdAt - a.createdAt));
});

app.post('/api/admin/notifications', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { title, content, type, target } = req.body || {};

  if (!title || !String(title).trim()) return res.status(400).json({ error: '标题不能为空' });
  if (!content || !String(content).trim()) return res.status(400).json({ error: '内容不能为空' });

  const notif = {
    id: genNotifId(),
    title: String(title).trim().slice(0, 100),
    content: String(content).trim().slice(0, 2000),
    type: ['info', 'success', 'warning', 'error'].includes(type) ? type : 'info',
    target: target || 'all',
    sender: 'admin',
    createdAt: Date.now(),
  };

  if (notif.target !== 'all') {
    const users = await kvGet('users') || {};
    if (!users[notif.target]) return res.status(404).json({ error: '目标用户不存在' });
  }

  const list = (await kvGet('notifications')) || [];
  list.push(notif);
  const trimmed = list.slice(-500);
  await kvPut('notifications', trimmed);
  res.json({ success: true, notification: notif });
});

app.delete('/api/admin/notifications/:id', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const id = req.params.id;
  const list = (await kvGet('notifications')) || [];
  const newList = list.filter(n => n.id !== id);
  await kvPut('notifications', newList);
  res.json({ success: true });
});

// ============================================================
//  后台管理 API
// ============================================================

app.get('/api/admin/users', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const users = await kvGet('users') || {};
  const list = await Promise.all(Object.entries(users).map(async ([username, data]) => {
    const avatar = await kvGet(`user_avatar:${username}`);
    const profile = await kvGet(`user_profile:${username}`) || {};
    return {
      username,
      role: data.role || 'user',
      displayName: profile.displayName || username,
      hasAvatar: !!avatar,
      createdAt: data.createdAt || null,
    };
  }));
  res.json(list);
});

app.delete('/api/admin/users', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: '缺少用户名' });
  if (username === 'admin') return res.status(400).json({ error: '不能删除管理员' });
  const users = await kvGet('users') || {};
  if (!users[username]) return res.status(404).json({ error: '用户不存在' });
  delete users[username];
  await kvPut('users', users);
  await kvDelete(`user_profile:${username}`);
  await kvDelete(`user_avatar:${username}`);
  await kvDelete(`notif_read:${username}`);
  await kvDelete(`notif_deleted:${username}`);
  await kvDelete(`chat_sessions:${username}`);
  await kvDelete(`chat_limit:${username}`);
  
  await kvDelete(`user_settings:${username}`);
  await kvDelete(`friends:${username}`);
  await kvDelete(`friend_requests:${username}`);
  await kvDelete(`friend_requests_out:${username}`);
  await kvDelete(`dm_convos:${username}`);
  
  try {
    const { removeUserFromAllFriends } = require('./social');
    await removeUserFromAllFriends(username);
  } catch (e) {}
  res.json({ success: true });
});

app.put('/api/admin/users/role', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { username, role } = req.body;
  if (!username || !role) return res.status(400).json({ error: '缺少参数' });
  if (role !== 'user' && role !== 'admin') return res.status(400).json({ error: '无效角色' });
  if (username === 'admin') return res.status(400).json({ error: '不能修改管理员角色' });
  const users = await kvGet('users') || {};
  if (!users[username]) return res.status(404).json({ error: '用户不存在' });
  users[username].role = role;
  await kvPut('users', users);
  res.json({ success: true });
});

app.post('/api/admin/reset-password', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { username, newPassword } = req.body;
  if (!username || !newPassword) return res.status(400).json({ error: '缺少参数' });
  if (username === 'admin') return res.status(400).json({ error: '不能重置管理员密码' });
  if (newPassword.length < 6) return res.status(400).json({ error: '密码至少6位' });
  const users = await kvGet('users') || {};
  if (!users[username]) return res.status(404).json({ error: '用户不存在' });
  const newRecord = await createUserRecord(newPassword);
  newRecord.role = users[username].role || 'user';
  newRecord.encryptedPassword = encryptPassword(newPassword);
  newRecord.createdAt = users[username].createdAt || Date.now();
  users[username] = newRecord;
  await kvPut('users', users);
  res.json({ success: true });
});

app.post('/api/admin/change-password', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });
  await kvPut('admin_password', newPassword);
  res.json({ success: true });
});

app.get('/api/admin/files', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const siteData = await kvGet('site_data') || { tools: [] };
  const tools = siteData.tools || [];
  const fileList = [];
  for (const tool of tools) {
    const id = tool.url.split('/').pop();
    const content = await kvGet(`tool_content:${id}`);
    fileList.push({ id, name: tool.name, icon: tool.icon, description: tool.description, category: tool.category || '其他', url: tool.url, size: content ? content.length : 0 });
  }
  res.json(fileList);
});

app.get('/api/admin/files/:id', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const content = await kvGet(`tool_content:${req.params.id}`);
  if (content === null) return res.status(404).json({ error: '文件不存在' });
  res.set('Content-Type', 'text/plain; charset=utf-8').send(content);
});

app.put('/api/admin/tools/:id', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { name, icon, description, category } = req.body;
  const siteData = await kvGet('site_data');
  if (!siteData || !siteData.tools) return res.status(404).json({ error: '工具列表不存在' });
  const tool = siteData.tools.find(t => t.url === `/tool/${req.params.id}`);
  if (!tool) return res.status(404).json({ error: '工具不存在' });
  if (name !== undefined) tool.name = name.slice(0,60);
  if (icon !== undefined) tool.icon = icon.slice(0,8);
  if (description !== undefined) tool.description = description.slice(0,300);
  if (category !== undefined) tool.category = category.slice(0,20);
  await kvPut('site_data', siteData);
  res.json({ success: true });
});

app.delete('/api/admin/files/:id', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const id = req.params.id;
  await kvDelete(`tool_content:${id}`);
  const siteData = await kvGet('site_data');
  if (siteData && siteData.tools) {
    siteData.tools = siteData.tools.filter(t => t.url !== `/tool/${id}`);
    await kvPut('site_data', siteData);
  }
  res.json({ success: true });
});

app.put('/api/admin/files/:id', upload.single('file'), async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const id = req.params.id;
  const file = req.file;
  if (!file || !file.originalname.toLowerCase().endsWith('.html')) {
    return res.status(400).json({ error: '请上传 .html 文件' });
  }
  const content = file.buffer.toString('utf8');
  if (!content.trim()) return res.status(400).json({ error: '文件内容为空' });
  await kvPut(`tool_content:${id}`, content);
  res.json({ success: true });
});

app.get('/api/admin/rooms', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  try {
    const list = await kvList({ prefix: 'gomoku:' });
    const rooms = [];
    for (const key of list.keys) {
      const roomId = key.name.replace('gomoku:', '');
      const room = await kvGet(key.name);
      if (!room) continue;
      rooms.push({
        roomId,
        creator: room.creator || '未知',
        status: room.status || 'unknown',
        playerCount: Object.keys(room.players || {}).length,
        onlineCount: Object.values(room.players || {}).filter(p => p?.online).length,
        hasPassword: !!room.password,
        createdAt: room.created || Date.now(),
        lastActive: room.lastActive || 0,
      });
    }
    rooms.sort((a,b) => b.createdAt - a.createdAt);
    res.json(rooms);
  } catch (err) {
    res.status(500).json({ error: '获取房间列表失败' });
  }
});

app.post('/api/admin/rooms/close', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  room.status = 'closed';
  await kvPut(key, room, { expirationTtl: 60 });
  res.json({ success: true });
});

app.post('/api/admin/verify-admin', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session || session.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  const { adminPassword } = req.body;
  if (!adminPassword) return res.status(400).json({ error: '请输入管理员密码' });
  let adminPwd = await kvGet('admin_password') || process.env.ADMIN;
  if (!adminPwd) return res.status(503).json({ error: '管理员账户尚未配置' });
  if (adminPassword !== adminPwd) return res.status(403).json({ error: '管理员密码错误' });
  const tempToken = crypto.randomUUID();
  const expires = Date.now() + 5 * 60 * 1000;
  await kvPut(`temp_admin:${tempToken}`, JSON.stringify({ expires }), { expirationTtl: 300 });
  res.json({ success: true, tempToken });
});

app.post('/api/admin/view-password', async (req, res) => {
  const adminToken = getBearerToken(req);
  const adminSession = await getSession(adminToken);
  if (!adminSession || adminSession.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  const { username, tempToken } = req.body;
  if (!username || !tempToken) return res.status(400).json({ error: '参数不完整' });
  const tempData = await kvGet(`temp_admin:${tempToken}`);
  if (!tempData || tempData.expires < Date.now()) {
    await kvDelete(`temp_admin:${tempToken}`);
    return res.status(403).json({ error: '临时令牌无效或已过期' });
  }
  await kvDelete(`temp_admin:${tempToken}`);
  const users = await kvGet('users') || {};
  const user = users[username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (username === 'admin') return res.status(400).json({ error: '不能查看管理员密码' });
  let plainPassword = null;
  if (user.encryptedPassword) {
    try { plainPassword = decryptPassword(user.encryptedPassword); } catch(e) { return res.status(500).json({ error: '解密失败' }); }
  } else {
    plainPassword = '（无法显示明文，请重置密码）';
  }
  res.json({ success: true, password: plainPassword });
});

// ============================================================
//  论坛系统
// ============================================================
const FORUM_CATEGORIES = [
  { id: 'general', name: '综合讨论', icon: '💬' },
  { id: 'tech', name: '技术交流', icon: '💻' },
  { id: 'share', name: '资源分享', icon: '🎁' },
  { id: 'help', name: '求助问答', icon: '❓' },
  { id: 'show', name: '作品展示', icon: '🎨' },
  { id: 'chat', name: '灌水闲聊', icon: '☕' },
];

function genPostId() { return 'P' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
function genCommentId() { return 'C' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

function extractLinks(text) {
  if (!text) return [];
  const re = /https?:\/\/[^\s<>"'\\)\]]+/gi;
  const matches = String(text).match(re) || [];
  return [...new Set(matches)].slice(0, 10);
}

async function getForumIndex() {
  const list = await kvGet('forum_index');
  return Array.isArray(list) ? list : [];
}
async function saveForumIndex(list) {
  await kvPut('forum_index', list.slice(0, 500));
}

async function decoratePosts(items) {
  if (!Array.isArray(items) || items.length === 0) return items;
  let usersCache = {};
  try { usersCache = (await kvGet('users')) || {}; } catch (e) {}
  const avatarCache = new Map();
  for (const item of items) {
    const author = item.author;
    if (!author) continue;
    if (!avatarCache.has(author)) {
      const av = await kvGet(`user_avatar:${author}`);
      avatarCache.set(author, !!av);
    }
    item.authorHasAvatar = avatarCache.get(author);
    if (author === 'admin') item.authorRole = 'admin';
    else item.authorRole = (usersCache[author] && usersCache[author].role) || 'user';
  }
  return items;
}

app.get('/api/forum/categories', async (req, res) => {
  res.json(FORUM_CATEGORIES);
});

app.get('/api/forum/stats', async (req, res) => {
  const index = await getForumIndex();
  res.json({
    totalPosts: index.length,
    totalViews: index.reduce((s, p) => s + (p.views || 0), 0),
    totalComments: index.reduce((s, p) => s + (p.commentCount || 0), 0),
  });
});

app.get('/api/forum/posts', async (req, res) => {
  const { category, q, sort = 'new', page = 1, limit = 15 } = req.query;
  let list = await getForumIndex();

  if (category && category !== 'all') {
    list = list.filter(p => p.category === category);
  }

  if (q && String(q).trim()) {
    const keyword = String(q).trim().toLowerCase();
    list = list.filter(p =>
      (p.title && p.title.toLowerCase().includes(keyword)) ||
      (p.excerpt && p.excerpt.toLowerCase().includes(keyword)) ||
      (p.authorDisplay && p.authorDisplay.toLowerCase().includes(keyword))
    );
  }

  if (sort === 'hot') {
    list.sort((a, b) => (b.likes || 0) - (a.likes || 0) || (b.commentCount || 0) - (a.commentCount || 0));
  } else if (sort === 'views') {
    list.sort((a, b) => (b.views || 0) - (a.views || 0));
  } else {
    list.sort((a, b) => b.createdAt - a.createdAt);
  }

  const pinned = list.filter(p => p.pinned);
  const normal = list.filter(p => !p.pinned);
  list = [...pinned, ...normal];

  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const pageSize = Math.min(50, Math.max(5, parseInt(limit, 10) || 15));
  const start = (pageNum - 1) * pageSize;
  const items = list.slice(start, start + pageSize);

  await decoratePosts(items);

  res.json({
    total: list.length,
    page: pageNum,
    pageSize,
    totalPages: Math.ceil(list.length / pageSize),
    items,
  });
});

app.post('/api/forum/posts', upload.array('images', 3), async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const { title, content, category = 'general', tags = '' } = req.body;
  if (!title || !String(title).trim()) return res.status(400).json({ error: '标题不能为空' });
  if (!content || !String(content).trim()) return res.status(400).json({ error: '内容不能为空' });

  const cleanTitle = String(title).trim().slice(0, 100);
  const cleanContent = String(content).trim().slice(0, 10000);
  const cleanCategory = FORUM_CATEGORIES.find(c => c.id === category) ? category : 'general';
  const cleanTags = String(tags).split(/[,\s，]+/).map(t => t.trim()).filter(Boolean).slice(0, 5);

  const images = [];
  if (req.files && req.files.length) {
    for (const file of req.files) {
      if (!/^image\/(jpeg|jpg|png|gif|webp)$/i.test(file.mimetype)) continue;
      if (file.size > 500 * 1024) continue;
      images.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
    }
  }

  const links = extractLinks(cleanContent);
  const profile = await getPublicProfile(session.username);
  const avatar = await kvGet(`user_avatar:${session.username}`);

  const now = Date.now();
  const post = {
    id: genPostId(),
    title: cleanTitle,
    content: cleanContent,
    excerpt: cleanContent.replace(/https?:\/\/\S+/g, '[链接]').slice(0, 150),
    author: session.username,
    authorDisplay: profile.displayName || session.username,
    authorAvatar: avatar ? `/api/user/avatar/${encodeURIComponent(session.username)}` : null,
    category: cleanCategory,
    tags: cleanTags,
    images,
    links,
    likes: [],
    views: 0,
    commentCount: 0,
    pinned: false,
    createdAt: now,
    updatedAt: now,
  };

  await kvPut(`forum_post:${post.id}`, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  index.unshift({
    id: post.id,
    title: post.title,
    excerpt: post.excerpt,
    author: post.author,
    authorDisplay: post.authorDisplay,
    category: post.category,
    tags: post.tags,
    hasImages: images.length > 0,
    hasLinks: links.length > 0,
    coverImage: images[0] || null,
    likes: 0,
    views: 0,
    commentCount: 0,
    pinned: false,
    createdAt: now,
  });
  await saveForumIndex(index);

  const userScore = (await kvGet(`forum_score:${session.username}`)) || 0;
  await kvPut(`forum_score:${session.username}`, userScore + 10);

  res.json({ success: true, postId: post.id });
});

app.get('/api/forum/posts/:id', async (req, res) => {
  const post = await kvGet(`forum_post:${req.params.id}`);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  res.json(post);
});

app.post('/api/forum/posts/:id/view', async (req, res) => {
  const key = `forum_post:${req.params.id}`;
  const post = await kvGet(key);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  post.views = (post.views || 0) + 1;
  await kvPut(key, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  const idx = index.findIndex(p => p.id === post.id);
  if (idx >= 0) {
    index[idx].views = post.views;
    await saveForumIndex(index);
  }
  res.json({ success: true, views: post.views });
});

app.post('/api/forum/posts/:id/like', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const key = `forum_post:${req.params.id}`;
  const post = await kvGet(key);
  if (!post) return res.status(404).json({ error: '帖子不存在' });

  if (!post.likes) post.likes = [];
  const idx = post.likes.indexOf(session.username);
  let liked;
  if (idx >= 0) {
    post.likes.splice(idx, 1);
    liked = false;
  } else {
    post.likes.push(session.username);
    liked = true;
  }
  await kvPut(key, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  const i = index.findIndex(p => p.id === post.id);
  if (i >= 0) {
    index[i].likes = post.likes.length;
    await saveForumIndex(index);
  }

  res.json({ success: true, liked, count: post.likes.length });
});

app.put('/api/forum/posts/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const key = `forum_post:${req.params.id}`;
  const post = await kvGet(key);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  if (post.author !== session.username && session.role !== 'admin') {
    return res.status(403).json({ error: '没有权限' });
  }

  const { title, content, tags } = req.body;
  if (title) post.title = String(title).trim().slice(0, 100);
  if (content) {
    post.content = String(content).trim().slice(0, 10000);
    post.excerpt = post.content.replace(/https?:\/\/\S+/g, '[链接]').slice(0, 150);
    post.links = extractLinks(post.content);
  }
  if (Array.isArray(tags)) post.tags = tags.slice(0, 5);
  post.updatedAt = Date.now();

  await kvPut(key, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  const i = index.findIndex(p => p.id === post.id);
  if (i >= 0) {
    index[i].title = post.title;
    index[i].excerpt = post.excerpt;
    index[i].tags = post.tags;
    index[i].hasLinks = post.links.length > 0;
    await saveForumIndex(index);
  }

  res.json({ success: true });
});

app.delete('/api/forum/posts/:id', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const key = `forum_post:${req.params.id}`;
  const post = await kvGet(key);
  if (!post) return res.status(404).json({ error: '帖子不存在' });
  if (post.author !== session.username && session.role !== 'admin') {
    return res.status(403).json({ error: '没有权限' });
  }

  await kvDelete(key);
  await kvDelete(`forum_comments:${req.params.id}`);

  const index = await getForumIndex();
  await saveForumIndex(index.filter(p => p.id !== req.params.id));

  res.json({ success: true });
});

app.post('/api/forum/posts/:id/pin', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });

  const key = `forum_post:${req.params.id}`;
  const post = await kvGet(key);
  if (!post) return res.status(404).json({ error: '帖子不存在' });

  post.pinned = !post.pinned;
  await kvPut(key, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  const i = index.findIndex(p => p.id === post.id);
  if (i >= 0) {
    index[i].pinned = post.pinned;
    await saveForumIndex(index);
  }

  res.json({ success: true, pinned: post.pinned });
});

app.get('/api/forum/posts/:id/comments', async (req, res) => {
  const comments = (await kvGet(`forum_comments:${req.params.id}`)) || [];
  res.json(comments);
});

app.post('/api/forum/posts/:id/comments', upload.array('images', 2), async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const { content } = req.body;
  if (!content || !String(content).trim()) return res.status(400).json({ error: '内容不能为空' });

  const postKey = `forum_post:${req.params.id}`;
  const post = await kvGet(postKey);
  if (!post) return res.status(404).json({ error: '帖子不存在' });

  const images = [];
  if (req.files && req.files.length) {
    for (const file of req.files) {
      if (!/^image\/(jpeg|jpg|png|gif|webp)$/i.test(file.mimetype)) continue;
      if (file.size > 300 * 1024) continue;
      images.push(`data:${file.mimetype};base64,${file.buffer.toString('base64')}`);
    }
  }

  const profile = await getPublicProfile(session.username);
  const avatar = await kvGet(`user_avatar:${session.username}`);

  const comment = {
    id: genCommentId(),
    content: String(content).trim().slice(0, 2000),
    links: extractLinks(String(content)),
    images,
    author: session.username,
    authorDisplay: profile.displayName || session.username,
    authorAvatar: avatar ? `/api/user/avatar/${encodeURIComponent(session.username)}` : null,
    createdAt: Date.now(),
  };

  const comments = (await kvGet(`forum_comments:${req.params.id}`)) || [];
  comments.push(comment);
  await kvPut(`forum_comments:${req.params.id}`, comments.slice(-500), { expirationTtl: 90 * 24 * 3600 });

  post.commentCount = comments.length;
  await kvPut(postKey, post, { expirationTtl: 90 * 24 * 3600 });

  const index = await getForumIndex();
  const i = index.findIndex(p => p.id === post.id);
  if (i >= 0) {
    index[i].commentCount = comments.length;
    await saveForumIndex(index);
  }

  const userScore = (await kvGet(`forum_score:${session.username}`)) || 0;
  await kvPut(`forum_score:${session.username}`, userScore + 2);

  res.json({ success: true, comment });
});

app.delete('/api/forum/comments/:postId/:commentId', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });

  const comments = (await kvGet(`forum_comments:${req.params.postId}`)) || [];
  const idx = comments.findIndex(c => c.id === req.params.commentId);
  if (idx < 0) return res.status(404).json({ error: '评论不存在' });

  if (comments[idx].author !== session.username && session.role !== 'admin') {
    return res.status(403).json({ error: '没有权限' });
  }

  comments.splice(idx, 1);
  await kvPut(`forum_comments:${req.params.postId}`, comments, { expirationTtl: 90 * 24 * 3600 });

  const postKey = `forum_post:${req.params.postId}`;
  const post = await kvGet(postKey);
  if (post) {
    post.commentCount = comments.length;
    await kvPut(postKey, post, { expirationTtl: 90 * 24 * 3600 });
  }

  res.json({ success: true });
});

app.get('/api/forum/score/:username', async (req, res) => {
  const score = (await kvGet(`forum_score:${req.params.username}`)) || 0;
  res.json({ username: req.params.username, score });
});
// ======== 五子棋 REST 辅助接口 ========
app.post('/api/room/create', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { color, password, invite } = req.body;
  if (color !== 1 && color !== 2) return res.status(400).json({ error: '请选择执子颜色' });
  const roomId = crypto.randomUUID().slice(0, 6).toUpperCase();
  const now = Date.now();
  const room = {
    board: Array(15).fill().map(() => Array(15).fill(0)),
    currentPlayer: 1,
    gameOver: false,
    history: [],
    players: { [color]: { username: session.username, online: true, color: color } },
    creator: session.username,
    creatorColor: color,
    password: password || null,
    inviteToken: invite ? crypto.randomUUID() : null,
    status: 'waiting',
    lastActive: now,
    created: now,
    messages: [],
  };
  try {
    await kvPut(`gomoku:${roomId}`, room, { expirationTtl: 7200 });
    res.json({ success: true, roomId, color, inviteToken: room.inviteToken });
  } catch (err) {
    console.error('创建房间失败:', err);
    res.status(500).json({ error: '房间创建失败' });
  }
});

app.post('/api/room/join', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { roomId, password, inviteToken } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  if (room.status === 'closed' || room.status === 'finished') return res.status(400).json({ error: '房间已结束' });

  let validInvite = false;
  if (inviteToken && room.inviteToken && inviteToken === room.inviteToken) validInvite = true;
  if (!validInvite && room.password && room.password !== password) return res.status(403).json({ error: '密码错误' });

  const existingPlayer = Object.values(room.players).find(p => p.username === session.username);
  if (existingPlayer) {
    existingPlayer.online = true;
    room.lastActive = Date.now();
    const total = Object.keys(room.players).length;
    const online = Object.values(room.players).filter(p => p.online).length;
    room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
    await kvPut(key, room, { expirationTtl: 7200 });
    return res.json({ success: true, roomId, color: existingPlayer.color, action: 'reconnect' });
  }

  const occupiedColors = Object.keys(room.players).map(Number);
  let availableColor = null;
  if (room.status === 'waiting' || room.status === 'paused') {
    if (occupiedColors.length < 2) availableColor = occupiedColors.includes(1) ? 2 : 1;
    else return res.status(409).json({ error: '房间已满' });
  } else if (room.status === 'playing') {
    const offlinePlayer = Object.values(room.players).find(p => !p.online);
    if (offlinePlayer) {
      availableColor = offlinePlayer.color;
      delete room.players[offlinePlayer.color];
    } else return res.status(409).json({ error: '房间已满且无人离线' });
  } else return res.status(400).json({ error: '房间状态异常' });
  if (availableColor === null) return res.status(400).json({ error: '无法加入房间' });

  room.players[availableColor] = { username: session.username, online: true, color: availableColor };
  room.lastActive = Date.now();
  for (const p of Object.values(room.players)) p.online = true;
  const total = Object.keys(room.players).length;
  const online = Object.values(room.players).filter(p => p.online).length;
  room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
  await kvPut(key, room, { expirationTtl: 7200 });
  res.json({ success: true, roomId, color: availableColor, action: 'join' });
});

app.post('/api/room/leave', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  let playerFound = false;
  for (const color of Object.keys(room.players)) {
    if (room.players[color].username === session.username) {
      room.players[color].online = false;
      playerFound = true;
      break;
    }
  }
  if (!playerFound) return res.status(403).json({ error: '你不在该房间中' });
  const onlineCount = Object.values(room.players).filter(p => p.online).length;
  if (onlineCount === 0) {
    room.status = 'closed';
    await kvPut(key, room, { expirationTtl: 60 });
  } else {
    const total = Object.keys(room.players).length;
    room.status = (total === 1) ? 'waiting' : 'paused';
    await kvPut(key, room, { expirationTtl: 7200 });
  }
  res.json({ success: true });
});

app.post('/api/room/heartbeat', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  let updated = false;
  for (const color of Object.keys(room.players)) {
    if (room.players[color].username === session.username) {
      room.players[color].online = true;
      room.lastActive = Date.now();
      updated = true;
      break;
    }
  }
  if (!updated) return res.status(400).json({ error: '你不在该房间中' });
  const total = Object.keys(room.players).length;
  const online = Object.values(room.players).filter(p => p.online).length;
  room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
  await kvPut(key, room, { expirationTtl: 7200 });
  res.json({ success: true });
});

app.get('/api/rooms', async (req, res) => {
  try {
    const list = await kvList({ prefix: 'gomoku:' });
    const rooms = [];
    for (const key of list.keys) {
      const roomId = key.name.replace('gomoku:', '');
      const room = await kvGet(key.name);
      if (!room) continue;
      rooms.push({
        roomId,
        creator: room.creator || '未知',
        status: room.status || 'unknown',
        playerCount: Object.keys(room.players || {}).length,
        onlineCount: Object.values(room.players || {}).filter(p => p?.online).length,
        hasPassword: !!room.password,
        createdAt: room.created || Date.now()
      });
    }
    rooms.sort((a,b) => b.createdAt - a.createdAt);
    res.json(rooms);
  } catch (err) {
    res.json([]);
  }
});

app.get('/api/room/:roomId', async (req, res) => {
  const room = await kvGet(`gomoku:${req.params.roomId}`);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  const { password, inviteToken, ...safe } = room;
  res.json(safe);
});

// ======== WebSocket 实时联机（五子棋） ========
const roomCache = new Map();

async function getRoom(roomId) {
  if (roomCache.has(roomId)) return roomCache.get(roomId);
  const room = await kvGet(`gomoku:${roomId}`);
  if (room) roomCache.set(roomId, room);
  return room;
}
async function saveRoom(roomId, room) {
  roomCache.set(roomId, room);
  await kvPut(`gomoku:${roomId}`, room, { expirationTtl: 7200 });
}

io.on('connection', (socket) => {
  console.log('新连接:', socket.id);
  socket.data = {};

  socket.on('join-room', async ({ roomId, token, password, inviteToken }) => {
    try {
      const session = await getSession(token);
      if (!session) return socket.emit('error', '请先登录');
      const room = await getRoom(roomId);
      if (!room) return socket.emit('error', '房间不存在');
      if (room.status === 'closed' || room.status === 'finished') return socket.emit('error', '房间已结束');

      let valid = false;
      if (inviteToken && room.inviteToken === inviteToken) valid = true;
      if (!valid && room.password && room.password !== password) return socket.emit('error', '密码错误');

      let existingColor = null;
      for (const [color, p] of Object.entries(room.players)) {
        if (p.username === session.username) { existingColor = Number(color); break; }
      }
      if (existingColor) {
        room.players[existingColor].online = true;
        await saveRoom(roomId, room);
        socket.join(roomId);
        socket.data = { username: session.username, roomId, color: existingColor };
        io.to(roomId).emit('room-update', room);
        return socket.emit('joined', { color: existingColor, action: 'reconnect' });
      }

      const occupied = Object.keys(room.players).map(Number);
      let color = null;
      if (room.status === 'waiting' || room.status === 'paused') {
        if (occupied.length < 2) color = occupied.includes(1) ? 2 : 1;
        else return socket.emit('error', '房间已满');
      } else if (room.status === 'playing') {
        const offline = Object.values(room.players).find(p => !p.online);
        if (offline) {
          color = offline.color;
          delete room.players[color];
        } else return socket.emit('error', '房间已满且无人离线');
      } else return socket.emit('error', '房间状态异常');

      room.players[color] = { username: session.username, online: true, color };
      const total = Object.keys(room.players).length;
      const online = Object.values(room.players).filter(p => p.online).length;
      room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
      room.lastActive = Date.now();
      await saveRoom(roomId, room);
      socket.join(roomId);
      socket.data = { username: session.username, roomId, color };
      io.to(roomId).emit('room-update', room);
      socket.emit('joined', { color, action: 'join' });
    } catch (e) {
      socket.emit('error', e.message);
    }
  });

  socket.on('make-move', async ({ roomId, row, col }) => {
    try {
      if (!socket.data?.roomId || socket.data.roomId !== roomId) return socket.emit('error', '未加入房间');
      const room = await getRoom(roomId);
      if (!room) return socket.emit('error', '房间不存在');
      if (room.gameOver) return socket.emit('error', '游戏已结束');
      if (room.status !== 'playing') return socket.emit('error', '游戏未开始');
      const playerEntry = Object.values(room.players).find(p => p.username === socket.data.username && p.online);
      if (!playerEntry) return socket.emit('error', '你不在房间或已离线');
      const player = playerEntry.color;
      if (room.currentPlayer !== player) return socket.emit('error', '不是你的回合');
      if (room.board[row][col] !== 0) return socket.emit('error', '该位置已有棋子');
      
      room.board[row][col] = player;
      room.history.push({ row, col });
      const win = checkWin(row, col, player, room.board);
      if (win) {
        room.gameOver = true;
        room.winner = player;
        room.status = 'finished';
      } else if (room.history.length === 225) {
        room.gameOver = true;
        room.winner = 0;
        room.status = 'finished';
      } else {
        room.currentPlayer = player === 1 ? 2 : 1;
      }
      room.lastActive = Date.now();
      await saveRoom(roomId, room);
      io.to(roomId).emit('room-update', room);
    } catch (e) {
      socket.emit('error', e.message);
    }
  });

  socket.on('send-message', async ({ roomId, text }) => {
    try {
      if (!socket.data?.roomId || socket.data.roomId !== roomId) return;
      if (!text || text.length > 200) return;
      const room = await getRoom(roomId);
      if (!room) return;
      if (!room.messages) room.messages = [];
      room.messages.push({ username: socket.data.username, text, time: Date.now() });
      if (room.messages.length > 100) room.messages = room.messages.slice(-100);
      await saveRoom(roomId, room);
      io.to(roomId).emit('new-message', { username: socket.data.username, text });
    } catch (e) {}
  });

  socket.on('disconnect', async () => {
    if (!socket.data?.roomId) return;
    const room = await getRoom(socket.data.roomId);
    if (!room) return;
    const color = socket.data.color;
    if (room.players[color]) {
      room.players[color].online = false;
      const total = Object.keys(room.players).length;
      const online = Object.values(room.players).filter(p => p.online).length;
      room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
      room.lastActive = Date.now();
      await saveRoom(socket.data.roomId, room);
      io.to(socket.data.roomId).emit('room-update', room);
    }
  });
});

function checkWin(row, col, player, board) {
  const dirs = [[0,1],[1,0],[1,1],[1,-1]];
  for (const [dr, dc] of dirs) {
    let count = 1;
    for (let d = 1; d < 5; d++) {
      const r = row + dr * d, c = col + dc * d;
      if (r<0||r>=15||c<0||c>=15||board[r][c]!==player) break;
      count++;
    }
    for (let d = 1; d < 5; d++) {
      const r = row - dr * d, c = col - dc * d;
      if (r<0||r>=15||c<0||c>=15||board[r][c]!==player) break;
      count++;
    }
    if (count >= 5) return true;
  }
  return false;
}

// ============================================================
//  挂载社交模块（私聊 / 好友 / 用户主页 / 论坛收藏转发）
// ============================================================
registerSocialRoutes(app, { checkAdmin, getSession, io });
registerSocialSocket(io, { getSession });

// ======== 启动服务器 ========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ GreenBox 服务运行在 http://0.0.0.0:${PORT}`);
  console.log(`🔌 WebSocket 已就绪（五子棋 + 私聊）`);
  console.log(`💬 社交模块已挂载（好友 / 私聊 / 用户主页 / 收藏 / 转发）`);
});