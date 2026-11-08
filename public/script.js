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

    // 个人中心页面本身不再显示“其它”入口
    var isProfilePage = /\/profile(\.html)?\/?$/i.test(location.pathname || '');
    var existingOther = document.getElementById('other-nav');
    if (isProfilePage) {
      if (existingOther) existingOther.style.display = 'none';
      return;
    }

    if (!existingOther) {
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

  function boot() {
    setupNav();
    setupTour();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();