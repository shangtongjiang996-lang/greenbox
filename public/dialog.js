/**
 * 站内统一对话框：替代浏览器原生 alert/confirm/prompt。
 * 使用方式：
 *   await gbAlert('已保存');
 *   if (!(await gbConfirm('确定删除吗？'))) return;
 *   const name = await gbPrompt('请输入名称', '默认值');
 */
(function () {
  'use strict';
  if (window.gbDialogReady) return;
  window.gbDialogReady = true;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function ensureDialogStyles() {
    if (document.getElementById('gb-dialog-styles')) return;
    var style = document.createElement('style');
    style.id = 'gb-dialog-styles';
    style.textContent = [
      '.gb-dialog-overlay{position:fixed;inset:0;z-index:10020;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(15,23,42,.52);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);box-sizing:border-box;}',
      '.gb-dialog-card{width:min(440px,100%);max-width:100%;background:var(--card-bg,#fff);color:var(--text,#1b2b22);border:1px solid var(--border,#dbe7dc);border-radius:18px;box-shadow:0 24px 70px rgba(0,0,0,.26);overflow:hidden;padding:0;box-sizing:border-box;font-family:inherit;animation:gbDialogIn .2s ease-out;}',
      '@keyframes gbDialogIn{from{opacity:0;transform:translateY(8px) scale(.97)}to{opacity:1;transform:none}}',
      '.gb-dialog-card .modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:20px 22px 13px;border-bottom:1px solid var(--border,#dbe7dc);}',
      '.gb-dialog-card .modal-head h2{font-size:1.08rem;font-weight:800;line-height:1.4;margin:3px 0 0;color:var(--text,#1b2b22);}',
      '.gb-dialog-kicker{display:inline-block;font-size:11px;font-weight:800;color:var(--primary-dark,#166534);background:var(--primary-light,#dcfce7);border-radius:999px;padding:2px 8px;}',
      '.gb-dialog-card .modal-close{width:30px;height:30px;border:1px solid var(--border,#dbe7dc);background:var(--bg-alt,#f1f5f2);color:var(--muted,#64748b);border-radius:50%;font-size:18px;line-height:1;cursor:pointer;flex-shrink:0;}',
      '.gb-dialog-card .modal-body{padding:16px 22px 4px;}',
      '.gb-dialog-message{margin:0 0 12px;color:var(--muted,#52645a);font-size:14px;line-height:1.75;white-space:pre-wrap;word-break:break-word;}',
      '.gb-dialog-input{width:100%;box-sizing:border-box;margin:4px 0 2px;border:1px solid var(--border,#dbe7dc);border-radius:9px;background:var(--bg,#f6faf5);color:var(--text,#1b2b22);padding:10px 12px;font-family:inherit;font-size:14px;}',
      '.gb-dialog-input:focus{outline:2px solid var(--primary,#16a34a);outline-offset:1px;}',
      '.gb-dialog-card .modal-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 22px 18px;border-top:1px solid var(--border,#dbe7dc);}',
      '.gb-dialog-card .modal-foot button{min-height:36px;border-radius:9px;padding:7px 14px;font-family:inherit;font-size:13px;font-weight:700;cursor:pointer;}',
      '.gb-dialog-card .gb-dialog-cancel{background:transparent;border:1px solid var(--border,#dbe7dc);color:var(--muted,#52645a);}',
      '.gb-dialog-card .gb-dialog-ok{background:var(--primary,#16a34a);border:1px solid var(--primary,#16a34a);color:#fff;}',
      '.gb-dialog-card.danger .gb-dialog-ok{background:var(--danger,#dc2626);border-color:var(--danger,#dc2626);}',
      '.gb-dialog-card .modal-foot button:disabled{opacity:.55;cursor:not-allowed;}'
    ].join('');
    document.head.appendChild(style);
  }

  function openDialog(opts) {
    return new Promise(function (resolve) {
      ensureDialogStyles();
      var existing = document.querySelector('.gb-dialog-overlay');
      if (existing) existing.remove();
      var type = opts.type || 'alert';
      var danger = !!opts.danger;
      var overlay = document.createElement('div');
      overlay.className = 'modal-overlay show gb-dialog-overlay';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      overlay.setAttribute('aria-labelledby', 'gb-dialog-title');
      var badge = type === 'prompt' ? '输入信息' : type === 'confirm' ? '操作确认' : '提示';
      overlay.innerHTML =
        '<div class="modal-box gb-dialog-card' + (danger ? ' danger' : '') + '">' +
        '<div class="modal-head">' +
          '<div><div class="gb-dialog-kicker">' + badge + '</div>' +
          '<h2 id="gb-dialog-title">' + esc(opts.title || (type === 'alert' ? '提示' : '请确认')) + '</h2></div>' +
          '<button type="button" class="modal-close" data-dialog-cancel aria-label="关闭">×</button>' +
        '</div>' +
        '<div class="modal-body">' +
          '<p class="gb-dialog-message">' + esc(opts.message || '') + '</p>' +
          (type === 'prompt' ? '<input class="gb-dialog-input" type="text" value="' + esc(opts.defaultValue || '') + '" maxlength="' + (opts.maxlength || 200) + '" autocomplete="off">' : '') +
        '</div>' +
        '<div class="modal-foot">' +
          (type === 'alert' ? '' : '<button type="button" class="action-btn gb-dialog-cancel" data-dialog-cancel>取消</button>') +
          '<button type="button" class="comment-send gb-dialog-ok" data-dialog-ok>' + esc(opts.okText || '确定') + '</button>' +
        '</div></div>';
      document.body.appendChild(overlay);
      var lastFocus = document.activeElement;
      var input = overlay.querySelector('.gb-dialog-input');
      var done = false;
      function finish(value) {
        if (done) return;
        done = true;
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        try { if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus(); } catch (e) {}
        resolve(value);
      }
      function ok() { finish(type === 'prompt' ? String(input ? input.value : '') : true); }
      function cancel() { finish(type === 'prompt' ? null : false); }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); cancel(); return; }
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ok(); return; }
        if (e.key === 'Tab') {
          var nodes = Array.prototype.slice.call(overlay.querySelectorAll('button, input, [href], [tabindex]:not([tabindex="-1"])'))
            .filter(function (el) { return !el.disabled && el.offsetParent !== null; });
          if (!nodes.length) return;
          var first = nodes[0], last = nodes[nodes.length - 1];
          if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
          else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
      overlay.querySelector('[data-dialog-ok]').addEventListener('click', ok);
      var cancelBtns = overlay.querySelectorAll('[data-dialog-cancel]');
      Array.prototype.forEach.call(cancelBtns, function (b) { b.addEventListener('click', cancel); });
      overlay.addEventListener('click', function (e) { if (e.target === overlay) cancel(); });
      document.addEventListener('keydown', onKey);
      setTimeout(function () { if (input) { input.focus(); input.select(); } else { var b = overlay.querySelector('[data-dialog-ok]'); if (b) b.focus(); } }, 30);
    });
  }

  window.gbAlert = function (message, opts) {
    return openDialog(Object.assign({ type: 'alert', message: String(message == null ? '' : message) }, opts || {}));
  };
  window.gbConfirm = function (message, opts) {
    return openDialog(Object.assign({ type: 'confirm', message: String(message == null ? '' : message) }, opts || {}));
  };
  window.gbPrompt = function (message, defaultValue, opts) {
    return openDialog(Object.assign({ type: 'prompt', message: String(message == null ? '' : message), defaultValue: defaultValue == null ? '' : String(defaultValue) }, opts || {}));
  };

  // 原生 alert 没有返回值，直接替换为统一弹窗
  if (!window.__gbNativeAlert) {
    window.__gbNativeAlert = window.alert;
    window.alert = function (message) { window.gbAlert(message); };
  }

  // 通用站内弹窗的 Esc 关闭与 Tab 焦点循环
  document.addEventListener('keydown', function (e) {
    if (document.querySelector('.gb-dialog-overlay')) return;
    var overlay = document.querySelector('.modal-overlay.show, .dm-modal-overlay.show, .avatar-modal-overlay.show, .gm-invite-overlay.show');
    if (!overlay) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      overlay.classList.remove('show');
      return;
    }
    if (e.key !== 'Tab') return;
    var nodes = Array.prototype.slice.call(overlay.querySelectorAll('button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])'))
      .filter(function (el) { return !el.disabled && el.offsetParent !== null; });
    if (!nodes.length) return;
    var first = nodes[0], last = nodes[nodes.length - 1];
    if (!overlay.contains(document.activeElement)) {
      e.preventDefault();
      first.focus();
    } else if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });

  // 通用弹窗的滚动锁定（管理后台等没有 script.js 的页面也生效）
  (function setupModalScrollLock() {
    var selectors = '.modal, .modal-overlay, .dm-modal-overlay, .avatar-modal-overlay, .gm-invite-overlay, .gb-dialog-overlay, .ai-chat-panel.open, .ai-update-modal, .notif-panel.show, .notif-panel-overlay.show, .gb-major-overlay';
    var locked = false;
    var prevHtml = '';
    var prevBody = '';
    function visible(el) {
      var cs = getComputedStyle(el);
      if (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0) return false;
      var r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    }
    function sync() {
      var open = Array.prototype.some.call(document.querySelectorAll(selectors), visible);
      if (open === locked) return;
      if (open) {
        prevHtml = document.documentElement.style.overflow;
        prevBody = document.body.style.overflow;
        document.documentElement.style.overflow = 'hidden';
        document.body.style.overflow = 'hidden';
        document.documentElement.classList.add('gb-scroll-locked');
        document.body.classList.add('gb-scroll-locked');
      } else {
        document.documentElement.style.overflow = prevHtml;
        document.body.style.overflow = prevBody;
        document.documentElement.classList.remove('gb-scroll-locked');
        document.body.classList.remove('gb-scroll-locked');
      }
      locked = open;
    }
    var observer = new MutationObserver(function () { requestAnimationFrame(sync); });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style', 'hidden', 'aria-hidden'] });
    sync();
  })();
})();
