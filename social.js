/**
 * social.js — 私聊 / 好友 / 用户主页 / 论坛收藏转发
 * 由 app.js 挂载
 */
const { kvGet, kvPut, kvDelete } = require('./redis');

// ============================================================
//  工具函数
// ============================================================
function convIdOf(a, b) {
  return 'p_' + [String(a), String(b)].sort().join('__');
}
async function getBearerToken(req) {
  const auth = req.headers.authorization;
  return auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// ============================================================
//  用户隐私设置
// ============================================================
const DEFAULT_SETTINGS = {
  allowStrangerMsg: true,     // 允许陌生人发起会话
  friendPolicy: 'confirm',    // direct | confirm | closed
  showOnline: true,           // 对外显示在线状态
  autoReply: '',              // 离线自动回复
};

async function getUserSettings(username) {
  const s = await kvGet(`user_settings:${username}`);
  if (!s || typeof s !== 'object') return { ...DEFAULT_SETTINGS };
  return {
    allowStrangerMsg: s.allowStrangerMsg !== false,
    friendPolicy: ['direct', 'confirm', 'closed'].includes(s.friendPolicy) ? s.friendPolicy : 'confirm',
    showOnline: s.showOnline !== false,
    autoReply: typeof s.autoReply === 'string' ? s.autoReply.slice(0, 200) : '',
  };
}

async function setUserSettings(username, patch) {
  const cur = await getUserSettings(username);
  const next = { ...cur };
  if (typeof patch.allowStrangerMsg === 'boolean') next.allowStrangerMsg = patch.allowStrangerMsg;
  if (['direct', 'confirm', 'closed'].includes(patch.friendPolicy)) next.friendPolicy = patch.friendPolicy;
  if (typeof patch.showOnline === 'boolean') next.showOnline = patch.showOnline;
  if (typeof patch.autoReply === 'string') next.autoReply = patch.autoReply.slice(0, 200);
  await kvPut(`user_settings:${username}`, next);
  return next;
}

// ============================================================
//  好友数据
// ============================================================
async function getFriends(username) {
  const l = await kvGet(`friends:${username}`);
  return Array.isArray(l) ? l : [];
}
async function saveFriends(username, list) {
  await kvPut(`friends:${username}`, list.slice(0, 500));
}
async function getIncomingRequests(username) {
  const l = await kvGet(`friend_requests:${username}`);
  return Array.isArray(l) ? l : [];
}
async function saveIncomingRequests(username, list) {
  await kvPut(`friend_requests:${username}`, list.slice(0, 100));
}
async function getOutgoingRequests(username) {
  const l = await kvGet(`friend_requests_out:${username}`);
  return Array.isArray(l) ? l : [];
}
async function saveOutgoingRequests(username, list) {
  await kvPut(`friend_requests_out:${username}`, list.slice(0, 100));
}

// ============================================================
//  会话 / 消息数据
// ============================================================
async function getConvos(username) {
  const l = await kvGet(`dm_convos:${username}`);
  return Array.isArray(l) ? l : [];
}
async function saveConvos(username, list) {
  await kvPut(`dm_convos:${username}`, list.slice(0, 200));
}
async function getMessages(convId) {
  const l = await kvGet(`dm_msgs:${convId}`);
  return Array.isArray(l) ? l : [];
}
async function saveMessages(convId, list) {
  await kvPut(`dm_msgs:${convId}`, list.slice(-1000), { expirationTtl: 180 * 24 * 3600 });
}
async function patchConvo(me, peer, patch) {
  const convId = convIdOf(me, peer);
  const convos = await getConvos(me);
  let idx = convos.findIndex(x => x.id === convId);
  if (idx < 0) {
    convos.unshift({
      id: convId, type: 'private', peer,
      lastMsg: '', lastTime: Date.now(),
      unread: 0, pinned: false, muted: false, createdAt: Date.now(),
      ...patch,
    });
  } else {
    convos[idx] = { ...convos[idx], ...patch };
  }
  await saveConvos(me, convos);
}
async function removeConvo(me, convId) {
  const convos = await getConvos(me);
  await saveConvos(me, convos.filter(x => x.id !== convId));
}

// ============================================================
//  公开资料
// ============================================================
async function publicProfile(username) {
  const profile = (await kvGet(`user_profile:${username}`)) || {};
  const avatar = await kvGet(`user_avatar:${username}`);
  const users = (await kvGet('users')) || {};
  let role = 'user';
  if (username === 'admin') role = 'admin';
  else if (users[username]) role = users[username].role || 'user';
  return {
    username,
    displayName: profile.displayName || (username === 'admin' ? '管理员' : username),
    bio: profile.bio || '',
    role,
    hasAvatar: !!avatar,
    createdAt: users[username] ? users[username].createdAt || null : null,
  };
}

// ============================================================
//  在线状态
// ============================================================
const onlineSockets = new Map(); // username -> Set<socket>
function isOnline(username) {
  const s = onlineSockets.get(username);
  return !!(s && s.size);
}
function addOnline(username, socket) {
  if (!onlineSockets.has(username)) onlineSockets.set(username, new Set());
  onlineSockets.get(username).add(socket);
}
function removeOnline(username, socket) {
  const set = onlineSockets.get(username);
  if (!set) return false;
  set.delete(socket);
  if (set.size === 0) { onlineSockets.delete(username); return true; }
  return false;
}
function emitToUser(io, username, event, data) {
  const set = onlineSockets.get(username);
  if (set) for (const s of set) { try { s.emit(event, data); } catch (e) {} }
}

// ============================================================
//  论坛索引辅助
// ============================================================
async function getForumIndex() {
  const list = await kvGet('forum_index');
  return Array.isArray(list) ? list : [];
}
async function getPostsByUser(username) {
  const idx = await getForumIndex();
  return idx.filter(p => p.author === username).sort((a, b) => b.createdAt - a.createdAt);
}

// ============================================================
//  投递消息（REST & WS 共用）
// ============================================================
async function deliverMessage(from, to, content, replyTo, io) {
  if (!to || to === from) return { error: '参数错误', code: 400 };
  content = String(content || '').trim();
  if (!content) return { error: '消息不能为空', code: 400 };
  const users = (await kvGet('users')) || {};
  if (!users[to] && to !== 'admin') return { error: '用户不存在', code: 404 };

  const myFriends = await getFriends(from);
  const theirFriends = await getFriends(to);
  if (theirFriends.some(f => f.username === from && f.blocked)) return { error: '对方已将你拉黑', code: 403 };
  if (myFriends.some(f => f.username === to && f.blocked)) return { error: '你已拉黑对方', code: 403 };

  const theirSettings = await getUserSettings(to);
  const isFriend = myFriends.some(f => f.username === to && !f.blocked);
  if (!isFriend && !theirSettings.allowStrangerMsg) return { error: '对方不接受陌生人消息', code: 403 };

  const convId = convIdOf(from, to);
  const msgs = await getMessages(convId);
  const msg = {
    id: 'M' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    from, to,
    content: content.slice(0, 2000),
    time: Date.now(),
    read: false,
    recalled: false,
    replyTo: replyTo ? String(replyTo).slice(0, 50) : undefined,
  };
  msgs.push(msg);
  await saveMessages(convId, msgs);

  const preview = msg.content.slice(0, 40);
  await patchConvo(from, to, { lastMsg: preview, lastTime: msg.time });
  await patchConvo(to, from, { lastMsg: preview, lastTime: msg.time });

  const toConvos = await getConvos(to);
  const ci = toConvos.findIndex(c => c.id === convId);
  if (ci >= 0) {
    toConvos[ci].unread = (toConvos[ci].unread || 0) + 1;
    await saveConvos(to, toConvos);
  }

  if (io) {
    emitToUser(io, to, 'dm:message', msg);
    emitToUser(io, from, 'dm:message', msg);
  }
  return { message: msg };
}
// ============================================================
//  REST 路由
// ============================================================
function registerSocialRoutes(app, deps) {
  const { getSession, io } = deps;
  const auth = async (req) => getSession(await getBearerToken(req));

  // ---------- 隐私设置 ----------
  app.get('/api/social/settings', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    res.json(await getUserSettings(s.username));
  });

  app.put('/api/social/settings', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const next = await setUserSettings(s.username, req.body || {});
    res.json({ success: true, settings: next });
  });

  // ---------- 用户公开主页 ----------
  app.get('/api/social/user/:username', async (req, res) => {
    const username = req.params.username;
    const users = (await kvGet('users')) || {};
    if (username !== 'admin' && !users[username]) return res.status(404).json({ error: '用户不存在' });

    const prof = await publicProfile(username);
    const st = await getUserSettings(username);
    const posts = await getPostsByUser(username);
    const friends = await getFriends(username);
    const me = await auth(req);

    let relation = 'none';
    if (me) {
      if (me.username === username) relation = 'self';
      else {
        const myFriends = await getFriends(me.username);
        const isFriend = myFriends.some(f => f.username === username && !f.blocked);
        const blockedByMe = myFriends.some(f => f.username === username && f.blocked);
        const blockedMe = friends.some(f => f.username === me.username && f.blocked);
        const myOut = await getOutgoingRequests(me.username);
        const theirOut = await getOutgoingRequests(username);
        if (blockedByMe) relation = 'blocked_by_me';
        else if (blockedMe) relation = 'blocked_me';
        else if (isFriend) relation = 'friend';
        else if (myOut.some(r => r.to === username)) relation = 'outgoing';
        else if (theirOut.some(r => r.to === me.username)) relation = 'incoming';
      }
    }

    res.json({
      ...prof,
      online: st.showOnline ? isOnline(username) : false,
      stats: {
        posts: posts.length,
        friends: friends.filter(f => !f.blocked).length,
      },
      settings: {
        allowStrangerMsg: st.allowStrangerMsg,
        friendPolicy: st.friendPolicy,
        showOnline: st.showOnline,
      },
      relation,
      canDM: relation !== 'self' && relation !== 'blocked_by_me' && relation !== 'blocked_me' && st.allowStrangerMsg,
      canFriendRequest: relation !== 'self' && relation !== 'blocked_by_me' && relation !== 'blocked_me'
        && relation !== 'friend' && relation !== 'outgoing' && st.friendPolicy !== 'closed',
      canAccept: relation === 'incoming',
      recentPosts: posts.slice(0, 20).map(p => ({
        id: p.id, title: p.title, excerpt: p.excerpt, category: p.category,
        createdAt: p.createdAt, likes: p.likes || 0, views: p.views || 0,
        commentCount: p.commentCount || 0, coverImage: p.coverImage || null,
      })),
    });
  });

  // ---------- 好友列表 ----------
  app.get('/api/social/friends', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const list = await getFriends(s.username);
    const out = [];
    for (const f of list) {
      const prof = await publicProfile(f.username);
      const st = await getUserSettings(f.username);
      out.push({
        username: f.username,
        displayName: f.remark || prof.displayName,
        remark: f.remark || '',
        hasAvatar: prof.hasAvatar,
        role: prof.role,
        since: f.since || null,
        muted: !!f.muted,
        blocked: !!f.blocked,
        online: st.showOnline ? isOnline(f.username) : false,
      });
    }
    out.sort((a, b) => (Number(b.online) - Number(a.online)) || (a.displayName || '').localeCompare(b.displayName || ''));
    res.json(out);
  });

  // ---------- 好友申请列表 ----------
  app.get('/api/social/friends/requests', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const inc = await getIncomingRequests(s.username);
    const incOut = [];
    for (const r of inc) {
      const prof = await publicProfile(r.from);
      incOut.push({ ...r, fromDisplay: prof.displayName, fromAvatar: prof.hasAvatar, fromRole: prof.role });
    }
    const out = await getOutgoingRequests(s.username);
    res.json({ incoming: incOut, outgoing: out });
  });

  // ---------- 发送好友申请 ----------
  app.post('/api/social/friends/request', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { username, message } = req.body || {};
    if (!username || username === s.username) return res.status(400).json({ error: '参数错误' });
    const users = (await kvGet('users')) || {};
    if (!users[username] && username !== 'admin') return res.status(404).json({ error: '用户不存在' });

    const targetSettings = await getUserSettings(username);
    if (targetSettings.friendPolicy === 'closed') return res.status(403).json({ error: '对方不接受好友申请' });

    const myFriends = await getFriends(s.username);
    if (myFriends.some(f => f.username === username && !f.blocked)) {
      return res.json({ success: true, auto: false, msg: '你们已经是好友' });
    }

    const theirFriends = await getFriends(username);
    if (theirFriends.some(f => f.username === s.username && f.blocked)) return res.status(403).json({ error: '对方已将你拉黑' });
    if (myFriends.some(f => f.username === username && f.blocked)) return res.status(403).json({ error: '你已拉黑对方' });

    if (targetSettings.friendPolicy === 'direct') {
      const since = Date.now();
      if (!myFriends.some(f => f.username === username)) {
        myFriends.push({ username, since, remark: '', muted: false, blocked: false });
        await saveFriends(s.username, myFriends);
      }
      if (!theirFriends.some(f => f.username === s.username)) {
        theirFriends.push({ username: s.username, since, remark: '', muted: false, blocked: false });
        await saveFriends(username, theirFriends);
      }
      if (io) {
        emitToUser(io, username, 'social:friend-added', { by: s.username });
        emitToUser(io, s.username, 'social:friend-added', { by: username });
      }
      return res.json({ success: true, auto: true, msg: '已添加为好友' });
    }

    const theirIn = await getIncomingRequests(username);
    if (theirIn.some(r => r.from === s.username)) {
      return res.json({ success: true, auto: false, msg: '申请已发送，请等待对方确认' });
    }
    theirIn.push({
      id: 'R' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
      from: s.username,
      message: String(message || '').slice(0, 100),
      createdAt: Date.now(),
    });
    await saveIncomingRequests(username, theirIn);

    const myOut = await getOutgoingRequests(s.username);
    myOut.push({ to: username, message: String(message || '').slice(0, 100), createdAt: Date.now() });
    await saveOutgoingRequests(s.username, myOut.slice(-100));

    if (io) emitToUser(io, username, 'social:friend-request', { from: s.username });
    res.json({ success: true, auto: false, msg: '好友申请已发送' });
  });

  // ---------- 接受好友申请 ----------
  app.post('/api/social/friends/accept', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { from } = req.body || {};
    if (!from) return res.status(400).json({ error: '参数错误' });
    const inc = await getIncomingRequests(s.username);
    const idx = inc.findIndex(r => r.from === from);
    if (idx < 0) return res.status(404).json({ error: '申请不存在' });
    inc.splice(idx, 1);
    await saveIncomingRequests(s.username, inc);

    const theirOut = await getOutgoingRequests(from);
    await saveOutgoingRequests(from, theirOut.filter(r => r.to !== s.username));

    const since = Date.now();
    const myFriends = await getFriends(s.username);
    if (!myFriends.some(f => f.username === from)) {
      myFriends.push({ username: from, since, remark: '', muted: false, blocked: false });
      await saveFriends(s.username, myFriends);
    }
    const theirFriends = await getFriends(from);
    if (!theirFriends.some(f => f.username === s.username)) {
      theirFriends.push({ username: s.username, since, remark: '', muted: false, blocked: false });
      await saveFriends(from, theirFriends);
    }
    if (io) {
      emitToUser(io, from, 'social:friend-added', { by: s.username });
      emitToUser(io, s.username, 'social:friend-added', { by: from });
    }
    res.json({ success: true });
  });

  // ---------- 拒绝好友申请 ----------
  app.post('/api/social/friends/reject', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { from } = req.body || {};
    const inc = await getIncomingRequests(s.username);
    await saveIncomingRequests(s.username, inc.filter(r => r.from !== from));
    const theirOut = await getOutgoingRequests(from);
    await saveOutgoingRequests(from, theirOut.filter(r => r.to !== s.username));
    res.json({ success: true });
  });

  // ---------- 删除好友 ----------
  app.delete('/api/social/friends/:username', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const other = req.params.username;
    await saveFriends(s.username, (await getFriends(s.username)).filter(f => f.username !== other));
    await saveFriends(other, (await getFriends(other)).filter(f => f.username !== s.username));
    await removeConvo(s.username, convIdOf(s.username, other));
    await removeConvo(other, convIdOf(s.username, other));
    res.json({ success: true });
  });

  // ---------- 拉黑 / 解除拉黑 ----------
  app.post('/api/social/friends/block', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { username, blocked } = req.body || {};
    if (!username) return res.status(400).json({ error: '参数错误' });
    const list = await getFriends(s.username);
    const idx = list.findIndex(f => f.username === username);
    if (idx < 0) list.push({ username, since: Date.now(), remark: '', muted: false, blocked: !!blocked });
    else list[idx].blocked = !!blocked;
    await saveFriends(s.username, list);
    res.json({ success: true });
  });

  // ---------- 好友备注 ----------
  app.post('/api/social/friends/remark', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { username, remark } = req.body || {};
    const list = await getFriends(s.username);
    const idx = list.findIndex(f => f.username === username);
    if (idx >= 0) list[idx].remark = String(remark || '').slice(0, 20);
    await saveFriends(s.username, list);
    res.json({ success: true });
  });

  // ---------- 会话列表 ----------
  app.get('/api/social/dm/convos', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const convos = await getConvos(s.username);
    const out = [];
    for (const c of convos) {
      const prof = await publicProfile(c.peer);
      const st = await getUserSettings(c.peer);
      out.push({
        ...c,
        peerName: prof.displayName,
        peerAvatar: prof.hasAvatar,
        peerRole: prof.role,
        online: st.showOnline ? isOnline(c.peer) : false,
      });
    }
    out.sort((a, b) => (Number(b.pinned) - Number(a.pinned)) || ((b.lastTime || 0) - (a.lastTime || 0)));
    res.json(out);
  });

  // ---------- 新建会话 ----------
  app.post('/api/social/dm/convos', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { peer } = req.body || {};
    if (!peer || peer === s.username) return res.status(400).json({ error: '参数错误' });
    const users = (await kvGet('users')) || {};
    if (!users[peer] && peer !== 'admin') return res.status(404).json({ error: '用户不存在' });

    const theirSettings = await getUserSettings(peer);
    const myFriends = await getFriends(s.username);
    const isFriend = myFriends.some(f => f.username === peer && !f.blocked);
    if (!isFriend && !theirSettings.allowStrangerMsg) return res.status(403).json({ error: '对方不接受陌生人消息' });
    const theirFriends = await getFriends(peer);
    if (theirFriends.some(f => f.username === s.username && f.blocked)) return res.status(403).json({ error: '对方已将你拉黑' });
    if (myFriends.some(f => f.username === peer && f.blocked)) return res.status(403).json({ error: '你已拉黑对方' });

    await patchConvo(s.username, peer, {});
    await patchConvo(peer, s.username, {});
    const convId = convIdOf(s.username, peer);
    res.json({ success: true, convId });
  });

  // ---------- 拉取消息 ----------
  app.get('/api/social/dm/messages/:convId', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const convId = req.params.convId;
    if (!convId.startsWith('p_')) return res.status(400).json({ error: '非法会话' });
    const parts = convId.slice(2).split('__');
    if (parts.length !== 2 || !parts.includes(s.username)) return res.status(403).json({ error: '无权访问' });
    const msgs = await getMessages(convId);
    res.json(msgs.slice(-200));
  });

  // ---------- 发送消息（REST 备用） ----------
  app.post('/api/social/dm/messages', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { to, content, replyTo } = req.body || {};
    const result = await deliverMessage(s.username, to, content, replyTo, io);
    if (result.error) return res.status(result.code || 400).json({ error: result.error });
    res.json({ success: true, message: result.message });
  });

  // ---------- 标记已读 ----------
  app.post('/api/social/dm/read', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { convId } = req.body || {};
    const convos = await getConvos(s.username);
    const idx = convos.findIndex(c => c.id === convId);
    if (idx >= 0) { convos[idx].unread = 0; await saveConvos(s.username, convos); }
    const msgs = await getMessages(convId);
    let changed = false;
    for (const m of msgs) { if (m.to === s.username && !m.read) { m.read = true; changed = true; } }
    if (changed) await saveMessages(convId, msgs);
    res.json({ success: true });
  });

  // ---------- 撤回消息 ----------
  app.post('/api/social/dm/recall', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { convId, msgId } = req.body || {};
    const msgs = await getMessages(convId);
    const idx = msgs.findIndex(m => m.id === msgId);
    if (idx < 0) return res.status(404).json({ error: '消息不存在' });
    if (msgs[idx].from !== s.username) return res.status(403).json({ error: '只能撤回自己的消息' });
    if (Date.now() - msgs[idx].time > 2 * 60 * 1000) return res.status(400).json({ error: '超过2分钟无法撤回' });
    msgs[idx].recalled = true;
    msgs[idx].content = '';
    await saveMessages(convId, msgs);
    if (io) {
      emitToUser(io, msgs[idx].to, 'dm:recall', { convId, msgId });
      emitToUser(io, s.username, 'dm:recall', { convId, msgId });
    }
    res.json({ success: true });
  });

  // ---------- 置顶 / 免打扰 ----------
  app.post('/api/social/dm/convo/pin', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { convId, pinned } = req.body || {};
    const convos = await getConvos(s.username);
    const idx = convos.findIndex(c => c.id === convId);
    if (idx >= 0) { convos[idx].pinned = !!pinned; await saveConvos(s.username, convos); }
    res.json({ success: true });
  });
  app.post('/api/social/dm/convo/mute', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const { convId, muted } = req.body || {};
    const convos = await getConvos(s.username);
    const idx = convos.findIndex(c => c.id === convId);
    if (idx >= 0) { convos[idx].muted = !!muted; await saveConvos(s.username, convos); }
    res.json({ success: true });
  });

  // ---------- 删除会话 ----------
  app.delete('/api/social/dm/convo/:convId', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    await removeConvo(s.username, req.params.convId);
    res.json({ success: true });
  });

  // ---------- 论坛收藏 ----------
  app.post('/api/forum/posts/:id/favorite', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const id = req.params.id;
    const list = await kvGet(`forum_fav:${s.username}`);
    const arr = Array.isArray(list) ? list.slice() : [];
    const i = arr.indexOf(id);
    let favorited;
    if (i >= 0) { arr.splice(i, 1); favorited = false; }
    else { arr.unshift(id); favorited = true; }
    await kvPut(`forum_fav:${s.username}`, arr.slice(0, 500));
    res.json({ success: true, favorited, count: arr.length });
  });

  app.get('/api/forum/favorites', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const list = await kvGet(`forum_fav:${s.username}`);
    const arr = Array.isArray(list) ? list : [];
    const idx = await getForumIndex();
    const map = new Map(idx.map(p => [p.id, p]));
    const out = [];
    for (const id of arr) {
      const p = map.get(id);
      if (p) out.push(p);
    }
    res.json(out);
  });

  // ---------- 论坛转发 ----------
  app.post('/api/forum/posts/:id/repost', async (req, res) => {
    const s = await auth(req);
    if (!s) return res.status(401).json({ error: '请先登录' });
    const id = req.params.id;
    const post = await kvGet(`forum_post:${id}`);
    if (!post) return res.status(404).json({ error: '帖子不存在' });
    const { comment } = req.body || {};
    const list = await kvGet(`forum_repost:${id}`);
    const arr = Array.isArray(list) ? list.slice() : [];
    const i = arr.findIndex(r => r.by === s.username);
    const entry = { by: s.username, comment: String(comment || '').slice(0, 200), at: Date.now() };
    if (i >= 0) arr[i] = entry;
    else arr.unshift(entry);
    await kvPut(`forum_repost:${id}`, arr.slice(0, 200), { expirationTtl: 90 * 24 * 3600 });
    res.json({ success: true, count: arr.length });
  });

  app.get('/api/forum/posts/:id/reposts', async (req, res) => {
    const list = await kvGet(`forum_repost:${req.params.id}`);
    res.json(Array.isArray(list) ? list : []);
  });
}
// ============================================================
//  WebSocket
// ============================================================
function registerSocialSocket(io, deps) {
  const { getSession } = deps;
  const socketUsers = new Map(); // socket.id -> username

  io.on('connection', (socket) => {
    socket.on('dm:auth', async ({ token } = {}) => {
      try {
        const s = await getSession(token);
        if (!s) return socket.emit('dm:error', '请先登录');
        if (socketUsers.has(socket.id)) return;
        socketUsers.set(socket.id, s.username);
        addOnline(s.username, socket);
        const friends = await getFriends(s.username);
        for (const f of friends) {
          if (f.blocked) continue;
          const st = await getUserSettings(f.username);
          if (st.showOnline) emitToUser(io, f.username, 'dm:presence', { username: s.username, online: true });
        }
        socket.emit('dm:ready', { username: s.username });
      } catch (e) {
        socket.emit('dm:error', '认证失败');
      }
    });

    socket.on('dm:send', async (payload, cb) => {
      const from = socketUsers.get(socket.id);
      if (!from) return cb && cb({ error: '请先登录' });
      const result = await deliverMessage(from, payload?.to, payload?.content, payload?.replyTo, io);
      cb && cb(result);
    });

    socket.on('dm:typing', async ({ to } = {}) => {
      const from = socketUsers.get(socket.id);
      if (!from || !to) return;
      emitToUser(io, to, 'dm:typing', { from });
    });

    socket.on('dm:read', async ({ convId } = {}) => {
      const me = socketUsers.get(socket.id);
      if (!me || !convId) return;
      const msgs = await getMessages(convId);
      let changed = false;
      const peers = new Set();
      for (const m of msgs) {
        if (m.to === me && !m.read) { m.read = true; changed = true; peers.add(m.from); }
      }
      if (changed) {
        await saveMessages(convId, msgs);
        for (const p of peers) emitToUser(io, p, 'dm:read', { convId, by: me });
      }
    });

    socket.on('dm:recall', async ({ convId, msgId } = {}, cb) => {
      const me = socketUsers.get(socket.id);
      if (!me) return cb && cb({ error: '请先登录' });
      const msgs = await getMessages(convId);
      const idx = msgs.findIndex(m => m.id === msgId);
      if (idx < 0) return cb && cb({ error: '消息不存在' });
      if (msgs[idx].from !== me) return cb && cb({ error: '无权撤回' });
      if (Date.now() - msgs[idx].time > 2 * 60 * 1000) return cb && cb({ error: '超过2分钟无法撤回' });
      msgs[idx].recalled = true;
      msgs[idx].content = '';
      await saveMessages(convId, msgs);
      emitToUser(io, msgs[idx].to, 'dm:recall', { convId, msgId });
      emitToUser(io, me, 'dm:recall', { convId, msgId });
      cb && cb({ ok: true });
    });

    socket.on('disconnect', async () => {
      const u = socketUsers.get(socket.id);
      if (!u) return;
      socketUsers.delete(socket.id);
      const wasOffline = removeOnline(u, socket);
      if (wasOffline) {
        try {
          const friends = await getFriends(u);
          for (const f of friends) {
            if (f.blocked) continue;
            const st = await getUserSettings(f.username);
            if (st.showOnline) emitToUser(io, f.username, 'dm:presence', { username: u, online: false });
          }
        } catch (e) {}
      }
    });
  });
}

// ============================================================
//  工具：反向清理某用户的好友关系
//  用法：await removeUserFromAllFriends('alice')
//  场景：删除账号、管理员删除用户时调用
// ============================================================
async function removeUserFromAllFriends(username) {
  if (!username) return;
  try {
    // 1. 清空该用户自己的好友列表 / 申请 / 会话
    await saveFriends(username, []);
    await saveIncomingRequests(username, []);
    await saveOutgoingRequests(username, []);
    await saveConvos(username, []);

    // 2. 遍历所有用户，把他们好友列表里的该用户移除
    const users = (await kvGet('users')) || {};
    const allUsernames = Object.keys(users);
    for (const u of allUsernames) {
      if (u === username) continue;

      // 好友列表
      const list = await getFriends(u);
      const filtered = list.filter(f => f.username !== username);
      if (filtered.length !== list.length) {
        await saveFriends(u, filtered);
        // 顺便删掉这个会话
        await removeConvo(u, convIdOf(u, username));
      }

      // 收到的申请
      const inc = await getIncomingRequests(u);
      const incFiltered = inc.filter(r => r.from !== username);
      if (incFiltered.length !== inc.length) await saveIncomingRequests(u, incFiltered);

      // 发出的申请
      const out = await getOutgoingRequests(u);
      const outFiltered = out.filter(r => r.to !== username);
      if (outFiltered.length !== out.length) await saveOutgoingRequests(u, outFiltered);
    }
  } catch (e) {
    console.error('removeUserFromAllFriends error:', e);
  }
}

module.exports = {
  registerSocialRoutes,
  registerSocialSocket,
  isOnline,
  emitToUser,
  convIdOf,
  getUserSettings,
  setUserSettings,
  removeUserFromAllFriends,
};