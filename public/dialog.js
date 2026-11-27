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

  function openDialog(opts) {
    return new Promise(function (resolve) {
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
})();
