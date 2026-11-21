const THEME_ICON = {
  dark: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#sun"/></svg>',
  light: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#moon"/></svg>'
};

(function () {
  var root = document.documentElement;
  var VALID_MODES = ['system', 'light', 'dark'];
  var VALID_ACCENTS = ['green', 'blue', 'violet', 'orange', 'rose'];
  var toggle = document.getElementById('theme-toggle');
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function systemTheme() {
    return media && media.matches ? 'dark' : 'light';
  }

  function readMode() {
    try {
      var saved = localStorage.getItem('themeMode');
      if (VALID_MODES.indexOf(saved) >= 0) return saved;
      var legacy = localStorage.getItem('theme');
      if (legacy === 'dark' || legacy === 'light') return legacy;
    } catch (e) {}
    return 'system';
  }

  function resolvedTheme(mode) {
    return mode === 'system' ? systemTheme() : mode;
  }

  function updateToggleIcon() {
    if (!toggle) return;
    var current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    toggle.innerHTML = current === 'dark' ? THEME_ICON.dark : THEME_ICON.light;
  }

  function applyThemeMode(mode, options) {
    options = options || {};
    if (VALID_MODES.indexOf(mode) < 0) mode = 'system';
    var resolved = resolvedTheme(mode);
    root.setAttribute('data-theme', resolved);
    try {
      localStorage.setItem('themeMode', mode);
      localStorage.setItem('theme', resolved);
    } catch (e) {}
    updateToggleIcon();
    if (!options.silent) {
      window.dispatchEvent(new CustomEvent('gb-theme-change', { detail: { mode: mode, theme: resolved } }));
    }
    return resolved;
  }

  function applyAccent(accent, options) {
    options = options || {};
    if (VALID_ACCENTS.indexOf(accent) < 0) accent = 'green';
    root.setAttribute('data-accent', accent);
    try { localStorage.setItem('accent', accent); } catch (e) {}
    if (!options.silent) {
      window.dispatchEvent(new CustomEvent('gb-theme-change', { detail: { accent: accent } }));
    }
    return accent;
  }

  function getToken() {
    try { return localStorage.getItem('greenbox_token') || ''; } catch (e) { return ''; }
  }

  function saveCloud(patch) {
    var token = getToken();
    if (!token) {
      window.dispatchEvent(new CustomEvent('gb-settings-synced', { detail: { ok: true, local: true } }));
      return Promise.resolve(null);
    }
    return fetch('/api/user/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify(patch)
    }).then(function (res) {
      if (!res.ok) throw new Error('sync failed');
      return res.json();
    }).then(function (settings) {
      window.dispatchEvent(new CustomEvent('gb-settings-synced', { detail: { ok: true, settings: settings } }));
      return settings;
    }).catch(function () {
      window.dispatchEvent(new CustomEvent('gb-settings-synced', { detail: { ok: false } }));
      return null;
    });
  }

  window.GBTheme = {
    modes: VALID_MODES,
    accents: VALID_ACCENTS,
    getMode: readMode,
    getTheme: function () { return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light'; },
    getAccent: function () {
      try { return localStorage.getItem('accent') || root.getAttribute('data-accent') || 'green'; } catch (e) { return 'green'; }
    },
    setThemeMode: function (mode) {
      applyThemeMode(mode);
      return saveCloud({ themeMode: mode });
    },
    setAccent: function (accent) {
      applyAccent(accent);
      return saveCloud({ accent: accent });
    },
    sync: function () {
      var token = getToken();
      if (!token) return Promise.resolve(null);
      return fetch('/api/user/settings', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(function (res) { if (!res.ok) throw new Error('load failed'); return res.json(); })
        .then(function (settings) {
          applyThemeMode(settings.themeMode || 'system', { silent: true });
          applyAccent(settings.accent || 'green', { silent: true });
          window.dispatchEvent(new CustomEvent('gb-settings-loaded', { detail: settings }));
          return settings;
        }).catch(function () { return null; });
    }
  };

  applyThemeMode(readMode(), { silent: true });
  applyAccent((function () { try { return localStorage.getItem('accent') || 'green'; } catch (e) { return 'green'; } })(), { silent: true });

  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      window.GBTheme.setThemeMode(next);
    });
  }

  if (media) {
    var onSystemThemeChange = function () {
      if (readMode() === 'system') applyThemeMode('system', { silent: true });
    };
    if (media.addEventListener) media.addEventListener('change', onSystemThemeChange);
    else if (media.addListener) media.addListener(onSystemThemeChange);
  }

  // 登录后从云端恢复主题与强调色；未登录时只使用本地设置
  if (getToken()) {
    window.GBTheme.sync();
  }
})();

// ===== 导航：个人中心常显 + “其它”入口 =====
(function () {
  function getToken() {
    try { return localStorage.getItem('greenbox_token'); } catch (e) { return null; }
  }

  function setupNav() {
    var pn = document.getElementById('profile-nav');
    if (!pn) {
      // 兼容没有 id 的旧页面：找到指向个人中心的导航项
      var fallback = document.querySelector('.nav-links a[href="/profile.html"]')
        || document.querySelector('.nav-links a[href="profile.html"]');
      if (fallback) pn = fallback.parentNode;
    }
    if (!pn) return;
    pn.style.display = 'list-item';

    var link = pn.querySelector('a');
    if (link) {
      link.title = '登录后使用个人中心';
      link.addEventListener('click', async function (e) {
        if (getToken()) return;
        e.preventDefault();
        if (await gbConfirm('个人中心需要登录，是否现在去登录？', { title: '需要登录', okText: '去登录' })) {
          location.href = '/login.html?redirect=/profile.html';
        }
      });
    }

    if (!document.getElementById('other-nav')) {
      var li = document.createElement('li');
      li.id = 'other-nav';
      var a = document.createElement('a');
      a.href = '/other.html';
      a.textContent = '其它';
      li.appendChild(a);
      pn.parentNode.insertBefore(li, pn.nextSibling);
    }
  }

  // ===== 首次访问提示：箭头 + 小窗 =====
  function setupTour() {
    var KEY = 'gb_tour_v1';
    var seen = null;
    try { seen = localStorage.getItem(KEY); } catch (e) {}
    if (seen) return;

    var target = document.getElementById('aiChatBtn');
    if (!target) return;

    setTimeout(function showTour() {
      // 首页首次访问可能同时弹出 AI 更新提示，等它关掉再显示引导
      var modal = document.getElementById('aiUpdateModal');
      if (modal && getComputedStyle(modal).display !== 'none') {
        setTimeout(showTour, 1200);
        return;
      }
      var box = document.createElement('div');
      box.className = 'gb-tour';
      box.setAttribute('role', 'dialog');
      box.innerHTML =
        '<button type="button" class="gb-tour-close" aria-label="关闭">\u00d7</button>' +
        '<div class="gb-tour-title">第一次来？</div>' +
        '<div class="gb-tour-text">点右下角的 AI 助手，可以问工具怎么用，也能直接聊天。</div>' +
        '<div class="gb-tour-actions"><button type="button" class="gb-tour-ok">知道了</button></div>';
      document.body.appendChild(box);

      function close() {
        box.remove();
        try { localStorage.setItem(KEY, '1'); } catch (e) {}
      }
      box.querySelector('.gb-tour-close').addEventListener('click', close);
      box.querySelector('.gb-tour-ok').addEventListener('click', close);
      target.addEventListener('click', close, { once: true });
    }, 900);
  }

  // ===== 重大通知 / 五子棋邀请弹窗 =====
  var MAJOR_HIDDEN = 'gb_major_hidden';
  var MAJOR_SHOWN = 'gb_major_shown';
  var activeInvite = null;

  function readIdList(storage, key) {
    try {
      var list = JSON.parse(storage.getItem(key) || '[]');
      return Array.isArray(list) ? list : [];
    } catch (e) { return []; }
  }
  function addId(storage, key, id) {
    var list = readIdList(storage, key);
    if (list.indexOf(id) < 0) list.push(id);
    try { storage.setItem(key, JSON.stringify(list.slice(-200))); } catch (e) {}
  }
  function escHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function markNoticeRead(id) {
    var token = getToken();
    if (!token) return;
    fetch('/api/notifications/read', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ ids: [id] }),
      keepalive: true,
    }).catch(function () {});
  }

  // 五子棋邀请：顶部小窗，60 秒倒计时，可手动关闭；关闭后服务端标记已读，其他设备同步消失
  function showGomokuInvite(n) {
    if (!n || document.querySelector('.gb-invite-banner') || document.querySelector('.gb-major-overlay')) return;
    var link = (typeof n.link === 'string' && n.link.charAt(0) === '/') ? n.link : '/gomoku-online.html';
    var banner = document.createElement('div');
    banner.className = 'gb-invite-banner';
    banner.setAttribute('role', 'dialog');
    banner.innerHTML =
      '<button type="button" class="gb-invite-x" aria-label="关闭">\u00d7</button>' +
      '<div class="gb-invite-head"><span class="gb-invite-badge">五子棋邀请</span><span class="gb-invite-time">60s</span></div>' +
      '<div class="gb-invite-title">' + escHtml(n.title) + '</div>' +
      '<div class="gb-invite-text">' + escHtml(n.content) + '</div>' +
      '<div class="gb-invite-progress"><i></i></div>' +
      '<div class="gb-invite-actions"><button type="button" class="gb-invite-dismiss">关闭</button><a class="gb-invite-go" href="' + escHtml(link) + '">去下棋</a></div>';
    document.body.appendChild(banner);

    var timeEl = banner.querySelector('.gb-invite-time');
    var fill = banner.querySelector('.gb-invite-progress i');
    var total = 60000;
    var endAt = Date.now() + total;
    var timer = null;
    var done = false;

    function finish(markRead, remote) {
      if (done) return;
      done = true;
      if (timer) clearInterval(timer);
      banner.remove();
      if (activeInvite && activeInvite.id === n.id) activeInvite = null;
      addId(localStorage, MAJOR_HIDDEN, n.id);
      if (markRead) markNoticeRead(n.id);
      setTimeout(checkMajorNotices, 350);
    }

    activeInvite = { id: n.id, close: finish };

    function tick() {
      var left = Math.max(0, endAt - Date.now());
      timeEl.textContent = Math.ceil(left / 1000) + 's';
      fill.style.width = (left / total * 100) + '%';
      if (left <= 0) finish(true, false);
    }
    tick();
    timer = setInterval(tick, 200);

    banner.querySelector('.gb-invite-x').addEventListener('click', function () { finish(true, false); });
    banner.querySelector('.gb-invite-dismiss').addEventListener('click', function () { finish(true, false); });
    banner.querySelector('.gb-invite-go').addEventListener('click', function (e) {
      e.preventDefault();
      finish(true, false);
      setTimeout(function () { location.href = link; }, 30);
    });
  }

  function dismissNotice(id) {
    if (activeInvite && activeInvite.id === id) activeInvite.close(false, true);
  }

  function showSystemToast(n) {
    if (!n || !n.title) return;
    var host = document.getElementById('gb-system-toasts');
    if (!host) {
      host = document.createElement('div');
      host.id = 'gb-system-toasts';
      host.className = 'gb-system-toasts';
      document.body.appendChild(host);
    }
    var box = document.createElement('div');
    box.className = 'gb-system-toast';
    var title = document.createElement('b');
    title.textContent = n.title;
    var text = document.createElement('span');
    text.textContent = String(n.content || '').slice(0, 90);
    box.appendChild(title);
    box.appendChild(text);
    box.addEventListener('click', function () {
      if (typeof n.link === 'string' && n.link.charAt(0) === '/') location.href = n.link;
      else location.href = '/messages.html';
    });
    host.appendChild(box);
    setTimeout(function () { box.remove(); if (host && !host.children.length) host.remove(); }, 6000);
  }

  function showFriendRequestPopup(req) {
    if (!req || !req.from || document.querySelector('.gb-friend-request')) return;
    var overlay = document.createElement('div');
    overlay.className = 'gb-major-overlay gb-friend-request';
    overlay.innerHTML = '<div class="gb-major-card">' +
      '<div class="gb-major-badge info">好友申请</div>' +
      '<h3>' + escHtml(req.fromDisplay || req.from) + ' 想添加你为好友</h3>' +
      '<p>' + escHtml(req.message || '对方没有填写验证消息') + '</p>' +
      '<div class="gb-major-meta">@' + escHtml(req.from) + '</div>' +
      '<div class="gb-major-actions">' +
      '<button type="button" class="gb-major-ghost" data-fr="reject">拒绝</button>' +
      '<a class="gb-major-ghost" href="/user.html?u=' + encodeURIComponent(req.from) + '" data-fr="view">查看主页</a>' +
      '<button type="button" class="gb-major-go" data-fr="accept">同意</button>' +
      '</div></div>';
    document.body.appendChild(overlay);
    var busy = false;
    overlay.addEventListener('click', async function (e) {
      var btn = e.target.closest('[data-fr]');
      if (!btn || busy) return;
      var act = btn.getAttribute('data-fr');
      if (act === 'view') { overlay.remove(); return; }
      busy = true;
      btn.disabled = true;
      try {
        var res = await fetch('/api/social/friends/' + (act === 'accept' ? 'accept' : 'reject'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getToken() },
          body: JSON.stringify({ from: req.from })
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(data.error || '操作失败');
        overlay.remove();
        showDmSystemToast(act === 'accept' ? '已添加 ' + req.from + ' 为好友' : '已拒绝好友申请');
      } catch (err) {
        busy = false;
        btn.disabled = false;
        alert(err.message || '操作失败');
      }
    });
  }

  function showDmSystemToast(text) {
    var t = document.getElementById('gb-system-toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'gb-system-toast';
      t.className = 'gb-system-toast';
      document.body.appendChild(t);
    }
    t.textContent = text;
    t.classList.add('show');
    clearTimeout(showDmSystemToast._t);
    showDmSystemToast._t = setTimeout(function () { t.classList.remove('show'); }, 3000);
  }

  function checkFriendRequests() {
    var token = getToken();
    if (!token) return;
    fetch('/api/social/friends/requests', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !Array.isArray(data.incoming) || !data.incoming.length) return;
        if (document.querySelector('.gb-friend-request')) return;
        showFriendRequestPopup(data.incoming[0]);
      })
      .catch(function () {});
  }

  function showMajorNotice(n) {
    if (!n || document.querySelector('.gb-major-overlay') || document.querySelector('.gb-invite-banner')) return;
    var overlay = document.createElement('div');
    overlay.className = 'gb-major-overlay';
    overlay.setAttribute('role', 'dialog');
    var isGomoku = n.kind === 'gomoku';
    var badge = isGomoku ? '五子棋邀请' : '重大通知';
    var badgeClass = isGomoku ? 'gomoku' : (n.type || 'info');
    var link = (typeof n.link === 'string' && n.link.charAt(0) === '/') ? n.link : '';
    var card = document.createElement('div');
    card.className = 'gb-major-card';
    card.innerHTML =
      '<div class="gb-major-badge ' + badgeClass + '">' + badge + '</div>' +
      '<h3>' + escHtml(n.title) + '</h3>' +
      '<p>' + escHtml(n.content) + '</p>' +
      '<div class="gb-major-meta">来自 ' + escHtml(n.sender || 'admin') + ' · ' + new Date(n.createdAt).toLocaleString('zh-CN', { hour12: false }) + '</div>' +
      '<div class="gb-major-actions">' +
        '<button type="button" class="gb-major-ghost" data-act="later">稍后</button>' +
        '<button type="button" class="gb-major-ghost" data-act="never">不再显示</button>' +
        (link ? '<a class="gb-major-go" href="' + escHtml(link) + '" data-act="go">' + (isGomoku ? '去下棋' : '去看看') + '</a>' : '') +
      '</div>';
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    function close(permanent) {
      if (permanent) addId(localStorage, MAJOR_HIDDEN, n.id);
      else addId(sessionStorage, MAJOR_SHOWN, n.id);
      markNoticeRead(n.id);
      overlay.remove();
      setTimeout(checkMajorNotices, 350);
    }
    card.querySelector('[data-act="later"]').addEventListener('click', function () { close(false); });
    card.querySelector('[data-act="never"]').addEventListener('click', function () { close(true); });
    var go = card.querySelector('[data-act="go"]');
    if (go) go.addEventListener('click', function () { close(false); });
  }

  function checkMajorNotices() {
    var token = getToken();
    if (!token) return;
    if (activeInvite || document.querySelector('.gb-invite-banner') || document.querySelector('.gb-major-overlay')) return;
    var modal = document.getElementById('aiUpdateModal');
    if (modal && getComputedStyle(modal).display !== 'none') {
      setTimeout(checkMajorNotices, 1800);
      return;
    }
    fetch('/api/notifications/major', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (list) {
        if (!Array.isArray(list) || !list.length) return;
        var hidden = readIdList(localStorage, MAJOR_HIDDEN);
        var shown = readIdList(sessionStorage, MAJOR_SHOWN);
        var invite = null, major = null;
        for (var i = 0; i < list.length; i++) {
          if (hidden.indexOf(list[i].id) >= 0 || shown.indexOf(list[i].id) >= 0) continue;
          if (list[i].kind === 'gomoku') {
            if (!invite) invite = list[i];
          } else if (!major) {
            major = list[i];
          }
        }
        if (invite) showGomokuInvite(invite);
        else if (major) showMajorNotice(major);
      })
      .catch(function () {});
  }

  function setupMajorNotices() {
    if (!getToken()) return;
    setTimeout(checkMajorNotices, 2600);
    setInterval(checkMajorNotices, 60000);
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) checkMajorNotices();
    });
  }

  // ===== 全站在线状态 + 跨设备通知同步 =====
  function showDmToast(msg) {
    if (!msg || !msg.from || (!msg.to && !msg.groupId)) return;
    var me = '';
    try {
      var u = JSON.parse(localStorage.getItem('greenbox_user') || 'null');
      me = u && u.username ? u.username : '';
    } catch (e) {}
    if (!me || msg.from === me) return;
    if (!msg.groupId && msg.to !== me) return;

    var holder = document.getElementById('gb-dm-toasts');
    if (!holder) {
      holder = document.createElement('div');
      holder.id = 'gb-dm-toasts';
      holder.className = 'gb-dm-toasts';
      document.body.appendChild(holder);
    }
    while (holder.children.length >= 3) holder.removeChild(holder.firstChild);

    var toast = document.createElement('a');
    toast.className = 'gb-dm-toast';
    toast.href = msg.groupId
      ? '/messages.html?group=' + encodeURIComponent(msg.groupId)
      : '/messages.html?peer=' + encodeURIComponent(msg.from);
    var preview = String(msg.content || (msg.attachment ? '[附件]' : '')).slice(0, 120);
    var title = msg.groupId ? (msg.groupName || '群聊') + ' · ' + msg.from : msg.from;
    var initial = String(msg.from).slice(0, 1).toUpperCase();
    toast.innerHTML =
      '<span class="gb-dm-avatar"><img src="/api/user/avatar/' + encodeURIComponent(msg.from) + '?t=' + 1 + '" alt="" onerror="this.style.display=\'none\';this.parentNode.textContent=\'' + initial + '\'"></span>' +
      '<span class="gb-dm-body"><b>' + escHtml(title) + '</b><span>' + escHtml(preview) + '</span><small>点击查看</small></span>' +
      '<button type="button" class="gb-dm-close" aria-label="关闭">×</button>';
    var timer = setTimeout(function () { toast.remove(); }, 6500);
    toast.querySelector('.gb-dm-close').addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      clearTimeout(timer);
      toast.remove();
    });
    toast.addEventListener('click', function () { clearTimeout(timer); });
    holder.appendChild(toast);
  }

  function setupScrollLock() {
    var selectors = '.modal, .modal-overlay, .dm-modal-overlay, .modal-backdrop, .gb-modal-overlay, [role="dialog"], .lightbox, .image-viewer, .confirm-overlay, .action-sheet, .notif-panel-overlay.show, .notif-panel.show';
    var ignore = '.gb-tour, .gb-invite-banner, .gb-dm-toast, .gb-major-overlay';
    var locked = false;
    function visible(el) {
      if (el.closest(ignore)) return false;
      var cs = window.getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
      var r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }
    function sync() {
      var open = Array.prototype.some.call(document.querySelectorAll(selectors), visible);
      if (open === locked) return;
      locked = open;
      document.body.classList.toggle('gb-scroll-locked', open);
      document.documentElement.classList.toggle('gb-scroll-locked', open);
    }
    var observer = new MutationObserver(function () {
      window.requestAnimationFrame(sync);
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style', 'hidden', 'aria-hidden'] });
    sync();
  }

  function setupPresence() {
    if (!getToken() || window.__gbPresenceSocket) return;

    function connect() {
      if (!window.io) {
        if (document.querySelector('script[data-gb-presence]')) return;
        var loader = document.createElement('script');
        loader.src = '/socket.io/socket.io.js';
        loader.async = true;
        loader.setAttribute('data-gb-presence', '1');
        loader.onload = connect;
        loader.onerror = function () {};
        document.head.appendChild(loader);
        return;
      }
      if (window.__gbPresenceSocket) return;
      try {
        var socket = io({ transports: ['websocket', 'polling'] });
        window.__gbPresenceSocket = socket;
        socket.on('connect', function () {
          var token = getToken();
          if (token) socket.emit('dm:auth', { token: token });
        });
        socket.on('dm:message', function (msg) {
          showDmToast(msg);
        });
        socket.on('notification:read', function (data) {
          if (!data || !Array.isArray(data.ids)) return;
          data.ids.forEach(function (id) { dismissNotice(id); });
        });
        socket.on('notify:major', function () {
          checkMajorNotices();
        });
        socket.on('notify:update', function (n) {
          showSystemToast(n);
        });
        socket.on('social:friend-request', function (data) {
          if (!data || !data.from) return;
          showFriendRequestPopup({ from: data.from, message: data.message || '', fromDisplay: data.fromDisplay || data.from });
        });
        socket.on('social:friend-added', function () {
          var popup = document.querySelector('.gb-friend-request');
          if (popup) popup.remove();
        });
        socket.on('social:friend-rejected', function () {
          var popup = document.querySelector('.gb-friend-request');
          if (popup) popup.remove();
        });
      } catch (e) {}
    }

    if (window.io) { connect(); return; }
    var script = document.createElement('script');
    script.src = '/socket.io/socket.io.js';
    script.async = true;
    script.onload = connect;
    script.onerror = function () {};
    document.head.appendChild(script);
  }

  function showUpdateToast(reg) {
    if (!reg || document.getElementById('gb-update-toast')) return;
    var box = document.createElement('div');
    box.id = 'gb-update-toast';
    box.className = 'gb-update-toast';
    var text = document.createElement('span');
    text.textContent = 'GreenBox 有新版本';
    var button = document.createElement('button');
    button.type = 'button';
    button.textContent = '刷新';
    button.addEventListener('click', function () {
      if (reg.waiting) reg.waiting.postMessage({ type: 'SKIP_WAITING' });
      setTimeout(function () { location.reload(); }, 300);
    });
    box.appendChild(text);
    box.appendChild(button);
    document.body.appendChild(box);
  }

  function setupServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    navigator.serviceWorker.register('/sw.js').then(function (reg) {
      if (reg.waiting) showUpdateToast(reg);
      reg.addEventListener('updatefound', function () {
        var next = reg.installing;
        if (!next) return;
        next.addEventListener('statechange', function () {
          if (next.state === 'installed' && navigator.serviceWorker.controller) {
            showUpdateToast(reg);
          }
        });
      });
    }).catch(function () {});
  }

  function setupAppIcon() {
    if (document.querySelector('link[rel="apple-touch-icon"]')) return;
    var link = document.createElement('link');
    link.rel = 'apple-touch-icon';
    link.href = '/icon-192.png';
    document.head.appendChild(link);
  }

  function setupSettingsLink() {
    var right = document.querySelector('.navbar-right');
    if (!right || document.getElementById('settings-link')) return;
    var link = document.createElement('a');
    link.id = 'settings-link';
    link.className = 'nav-icon-link';
    link.href = '/settings.html';
    link.title = '主题与偏好设置';
    link.setAttribute('aria-label', '主题与偏好设置');
    link.innerHTML = '<svg class="ico" aria-hidden="true"><use href="/icons.svg#gear"/></svg>';
    var themeToggle = document.getElementById('theme-toggle');
    if (themeToggle && themeToggle.parentNode === right) right.insertBefore(link, themeToggle);
    else right.appendChild(link);
  }

  function setupNavActions() {
    var right = document.querySelector('.navbar-right');
    if (!right) return;

    if (!document.getElementById('nav-notification-link') && !document.getElementById('notifBtn') && !right.querySelector('a[href^="/notifications.html"]')) {
      var bell = document.createElement('a');
      bell.id = 'nav-notification-link';
      bell.className = 'nav-icon-link';
      bell.href = '/notifications.html';
      bell.title = '通知中心';
      bell.setAttribute('aria-label', '通知中心');
      bell.innerHTML = '<svg class="ico" aria-hidden="true"><use href="/icons.svg#bell"/></svg>';
      var anchor = document.getElementById('gb-feedback-link') || document.getElementById('settings-link') || document.getElementById('theme-toggle');
      if (anchor && anchor.parentNode === right) right.insertBefore(bell, anchor);
      else right.appendChild(bell);
    }

    if (document.getElementById('nav-auth-actions')) return;
    var token = getToken();
    var userArea = right.querySelector('.user-area');
    var hasUserArea = (userArea && userArea.children.length > 0) || (userArea && token) || right.querySelector('a[href^="/profile.html"]');
    var hasLogin = right.querySelector('a[href*="login.html"]');
    if (hasUserArea || hasLogin) return;

    var box = document.createElement('span');
    box.id = 'nav-auth-actions';
    box.className = 'nav-auth-actions';
    if (token) {
      var profile = document.createElement('a');
      profile.href = '/profile.html';
      profile.className = 'login';
      profile.textContent = '个人中心';
      box.appendChild(profile);
    } else {
      var login = document.createElement('a');
      login.href = '/login.html?redirect=' + encodeURIComponent(location.pathname + location.search);
      login.className = 'login';
      login.textContent = '登录';
      var register = document.createElement('a');
      register.href = '/register.html';
      register.className = 'register';
      register.textContent = '注册';
      box.appendChild(login);
      box.appendChild(register);
    }
    right.appendChild(box);
  }

  function setupFeedbackEntry() {
    if (location.pathname === '/feedback.html') return;
    if (document.getElementById('gb-feedback-link')) return;
    var right = document.querySelector('.navbar-right');
    if (!right) return;
    var link = document.createElement('a');
    link.id = 'gb-feedback-link';
    link.className = 'nav-icon-link';
    link.href = '/feedback.html?from=' + encodeURIComponent(location.pathname + location.search);
    link.title = '意见反馈';
    link.setAttribute('aria-label', '意见反馈');
    link.innerHTML = '<svg class="ico" aria-hidden="true"><use href="/icons.svg#chat"/></svg>';
    var anchor = document.getElementById('settings-link') || document.getElementById('theme-toggle');
    if (anchor && anchor.parentNode === right) right.insertBefore(link, anchor);
    else right.appendChild(link);
  }

  function setupInstallPrompt() {
    var deferredPrompt = null;
    function hide() {
      var el = document.getElementById('gb-install-btn');
      if (el) el.remove();
    }
    window.addEventListener('beforeinstallprompt', function (event) {
      event.preventDefault();
      deferredPrompt = event;
      if (document.getElementById('gb-install-btn')) return;
      var btn = document.createElement('button');
      btn.id = 'gb-install-btn';
      btn.className = 'gb-install-btn';
      btn.type = 'button';
      btn.textContent = '安装 GreenBox';
      btn.addEventListener('click', function () {
        if (!deferredPrompt) { hide(); return; }
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then(function () {
          deferredPrompt = null;
          hide();
        }).catch(hide);
      });
      document.body.appendChild(btn);
    });
    window.addEventListener('appinstalled', hide);
  }

  function boot() {
    setupNav();
    setupTour();
    setupMajorNotices();
    setTimeout(checkFriendRequests, 4200);
    setupPresence();
    setupServiceWorker();
    setupInstallPrompt();
    setupSettingsLink();
    setupFeedbackEntry();
    setupNavActions();
    setTimeout(setupNavActions, 700);
    setupScrollLock();
    setupAppIcon();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
