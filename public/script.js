const THEME_ICON = {
  dark: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#sun"/></svg>',
  light: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#moon"/></svg>'
};
const toggle = document.getElementById('theme-toggle');
if (toggle) {
  const currentTheme = localStorage.getItem('theme') || 
                       (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', currentTheme);
  toggle.innerHTML = currentTheme === 'dark' ? THEME_ICON.dark : THEME_ICON.light;

  toggle.addEventListener('click', () => {
    const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    toggle.innerHTML = theme === 'dark' ? THEME_ICON.dark : THEME_ICON.light;
  });
}

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
      link.addEventListener('click', function (e) {
        if (getToken()) return;
        e.preventDefault();
        if (window.confirm('个人中心需要登录，是否现在去登录？')) {
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
  function setupPresence() {
    if (!getToken() || window.__gbPresenceSocket) return;

    function connect() {
      if (!window.io || window.__gbPresenceSocket) return;
      try {
        var socket = io({ transports: ['websocket', 'polling'] });
        window.__gbPresenceSocket = socket;
        socket.on('connect', function () {
          var token = getToken();
          if (token) socket.emit('dm:auth', { token: token });
        });
        socket.on('notification:read', function (data) {
          if (!data || !Array.isArray(data.ids)) return;
          data.ids.forEach(function (id) { dismissNotice(id); });
        });
        socket.on('notify:major', function () {
          checkMajorNotices();
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

  function boot() {
    setupNav();
    setupTour();
    setupMajorNotices();
    setupPresence();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();