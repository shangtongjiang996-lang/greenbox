require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const crypto = require('crypto');
const { kvGet, kvPut, kvDelete, kvList, kvIncr } = require('./redis');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: 2 * 1024 * 1024 } 
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
  return { passwordHash, salt, iterations, algo: 'pbkdf2-sha256', role: 'user' };
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

// ======== REST API ========

// 注册
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

// 登录
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

// 验证 token
app.get('/api/verify', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ valid: false });
  const users = await kvGet('users') || {};
  const user = users[session.username];
  const needsUpgrade = user && (!user.encryptedPassword || user.algo !== 'pbkdf2-sha256');
  res.json({ valid: true, username: session.username, role: session.role, needsUpgrade });
});

// 登出
app.post('/api/logout', async (req, res) => {
  const token = getBearerToken(req);
  if (token) await kvDelete(`session:${token}`);
  res.json({ success: true });
});

// 修改密码
app.post('/api/change-my-password', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: '密码至少6位' });
  const users = await kvGet('users') || {};
  const user = users[session.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const newRecord = await createUserRecord(newPassword);
  newRecord.role = user.role || 'user';
  newRecord.encryptedPassword = encryptPassword(newPassword);
  users[session.username] = newRecord;
  await kvPut('users', users);
  res.json({ success: true });
});

// 删除账号
app.post('/api/delete-account', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  if (session.username === 'admin') return res.status(403).json({ error: '不能删除管理员' });
  const users = await kvGet('users') || {};
  delete users[session.username];
  await kvPut('users', users);
  await kvDelete(`session:${token}`);
  res.json({ success: true });
});

// 获取站点数据
app.get('/api/data', async (req, res) => {
  const data = await kvGet('site_data') || { tools: [], changelogs: [] };
  res.json(data);
});

// 更新站点数据（需管理员）
app.post('/api/update', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const clean = req.body;
  await kvPut('site_data', clean);
  res.json({ success: true });
});

// 上传工具（需管理员）
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

// 获取工具内容
app.get('/tool/:id', async (req, res) => {
  const html = await kvGet(`tool_content:${req.params.id}`);
  if (!html) return res.status(404).send('工具不存在');
  res.set('Content-Type', 'text/html; charset=utf-8').send(html);
});

// ======== 后台管理 API ========

app.get('/api/admin/users', async (req, res) => {
  if (!(await checkAdmin(req))) return res.status(403).json({ error: '需要管理员权限' });
  const users = await kvGet('users') || {};
  const list = Object.entries(users).map(([username, data]) => ({ username, role: data.role || 'user' }));
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

// ======== 五子棋 REST 辅助接口 ========

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
    currentPlayer: color === 1 ? 1 : 2,
    gameOver: false,
    history: [],
    players: { [color]: { username: session.username, online: true, color } },
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
    console.log(`✅ 房间创建成功: ${roomId}`);
    return res.json({ success: true, roomId, color, inviteToken: room.inviteToken });
  } catch (err) {
    console.error('创建房间失败:', err);
    return res.status(500).json({ error: '房间创建失败' });
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
    const onlinePlayers = Object.values(room.players).filter(p => p.online);
    if (onlinePlayers.length === 1) {
      const offlinePlayer = Object.values(room.players).find(p => !p.online);
      if (offlinePlayer) {
        availableColor = offlinePlayer.color;
        delete room.players[offlinePlayer.color];
      } else return res.status(409).json({ error: '房间已满且无人离线' });
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
  return res.json({ success: true, roomId, color: availableColor, action: 'join' });
});

app.get('/api/room/:roomId', async (req, res) => {
  const room = await kvGet(`gomoku:${req.params.roomId}`);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  const { password, inviteToken, ...safe } = room;
  res.json(safe);
});

app.post('/api/room/move', async (req, res) => {
  res.status(404).json({ error: '请使用 WebSocket 下棋' });
});

app.post('/api/room/undo', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  if (room.gameOver) return res.status(400).json({ error: '游戏已结束' });
  if (room.status !== 'playing') return res.status(400).json({ error: '游戏未开始或已暂停' });
  const playerEntry = Object.values(room.players).find(p => p.username === session.username && p.online);
  if (!playerEntry) return res.status(403).json({ error: '你不在该房间或已离线' });
  if (room.history.length === 0) return res.status(400).json({ error: '没有可悔的棋' });
  const last = room.history.pop();
  room.board[last.row][last.col] = 0;
  room.currentPlayer = room.currentPlayer === 1 ? 2 : 1;
  room.lastActive = Date.now();
  await kvPut(key, room, { expirationTtl: 7200 });
  res.json({ success: true });
});

app.post('/api/room/restart', async (req, res) => {
  const token = getBearerToken(req);
  const session = await getSession(token);
  if (!session) return res.status(401).json({ error: '请先登录' });
  const { roomId } = req.body;
  if (!roomId) return res.status(400).json({ error: '缺少房间号' });
  const key = `gomoku:${roomId}`;
  const room = await kvGet(key);
  if (!room) return res.status(404).json({ error: '房间不存在' });
  const playerEntry = Object.values(room.players).find(p => p.username === session.username && p.online);
  if (!playerEntry) return res.status(403).json({ error: '你不在该房间或已离线' });
  const onlineCount = Object.values(room.players).filter(p => p.online).length;
  if (onlineCount < 2) return res.status(400).json({ error: '需要两人都在线才能重新开始' });
  room.board = Array(15).fill().map(() => Array(15).fill(0));
  room.currentPlayer = room.creatorColor;
  room.gameOver = false;
  room.history = [];
  room.winner = null;
  room.status = 'playing';
  room.lastActive = Date.now();
  await kvPut(key, room, { expirationTtl: 7200 });
  res.json({ success: true });
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

app.post('/api/room/chat', async (req, res) => {
  res.status(404).json({ error: '请使用 WebSocket 聊天' });
});

// ======== WebSocket 实时联机 ========
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

io.on('connection', (socket) => {
  console.log('新连接:', socket.id);
  socket.data = {};

  // 加入房间（修复重连状态）
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

    // ----- 重连分支（已修复） -----
    if (existingColor !== null) {
      room.players[existingColor].online = true;

      // ✅ 修复：重新计算房间状态
      const total = Object.keys(room.players).length;
      const online = Object.values(room.players).filter(p => p.online).length;
      room.status = (total === 1) ? 'waiting' : (online === 2 ? 'playing' : 'paused');
      // 如果游戏已结束，入口已拦截，无需额外处理

      await saveRoom(roomId, room);
      socket.join(roomId);
      socket.data = { username: session.username, roomId, color: existingColor };
      io.to(roomId).emit('room-update', room);
      return socket.emit('joined', { color: existingColor, action: 'reconnect' });
    }

    // ----- 新玩家加入（保持不变） -----
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

  // 下棋
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

  // 聊天
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

  // 悔棋（WebSocket）
  socket.on('undo', async ({ roomId }) => {
    try {
      const room = await getRoom(roomId);
      if (!room) return socket.emit('error', '房间不存在');
      if (room.gameOver) return socket.emit('error', '游戏已结束');
      if (room.status !== 'playing') return socket.emit('error', '游戏未开始');
      const player = Object.values(room.players).find(p => p.username === socket.data.username && p.online);
      if (!player) return socket.emit('error', '你不在房间或已离线');
      if (room.history.length === 0) return socket.emit('error', '没有可悔的棋');
      const last = room.history.pop();
      room.board[last.row][last.col] = 0;
      room.currentPlayer = room.currentPlayer === 1 ? 2 : 1;
      room.lastActive = Date.now();
      await saveRoom(roomId, room);
      io.to(roomId).emit('room-update', room);
      socket.emit('undo-success', room);
    } catch (e) {
      socket.emit('error', e.message);
    }
  });

  // 重新开始（WebSocket）
  socket.on('restart', async ({ roomId }) => {
    try {
      const room = await getRoom(roomId);
      if (!room) return socket.emit('error', '房间不存在');
      const player = Object.values(room.players).find(p => p.username === socket.data.username && p.online);
      if (!player) return socket.emit('error', '你不在房间或已离线');
      const onlineCount = Object.values(room.players).filter(p => p.online).length;
      if (onlineCount < 2) return socket.emit('error', '需要两人都在线才能重新开始');
      room.board = Array(15).fill().map(() => Array(15).fill(0));
      room.currentPlayer = room.creatorColor;
      room.gameOver = false;
      room.history = [];
      room.winner = null;
      room.status = 'playing';
      room.lastActive = Date.now();
      await saveRoom(roomId, room);
      io.to(roomId).emit('room-update', room);
      socket.emit('restart-success', room);
    } catch (e) {
      socket.emit('error', e.message);
    }
  });

  // 断开连接
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

// ======== 启动服务器 ========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ GreenBox 服务运行在 http://0.0.0.0:${PORT}`);
  console.log(`🔌 WebSocket 已就绪`);
});