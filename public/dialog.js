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
      overlay.className = 'gb-major-overlay gb-dialog-overlay';
      overlay.setAttribute('role', 'dialog');
      overlay.setAttribute('aria-modal', 'true');
      var badge = type === 'prompt' ? '输入' : type === 'confirm' ? '确认操作' : '提示';
      overlay.innerHTML =
        '<div class="gb-major-card gb-dialog-card' + (danger ? ' danger' : '') + '">' +
        '<div class="gb-major-badge' + (danger ? ' warning' : '') + '">' + badge + '</div>' +
        '<h3>' + esc(opts.title || (type === 'alert' ? '提示' : '请确认')) + '</h3>' +
        '<p>' + esc(opts.message || '') + '</p>' +
        (type === 'prompt' ? '<input class="gb-dialog-input" type="text" value="' + esc(opts.defaultValue || '') + '" maxlength="' + (opts.maxlength || 200) + '" autocomplete="off">' : '') +
        '<div class="gb-major-actions">' +
        (type === 'alert' ? '' : '<button type="button" class="gb-major-ghost" data-dialog-cancel>取消</button>') +
        '<button type="button" class="gb-major-go" data-dialog-ok>' + esc(opts.okText || '确定') + '</button>' +
        '</div></div>';
      document.body.appendChild(overlay);
      var input = overlay.querySelector('.gb-dialog-input');
      var done = false;
      function finish(value) {
        if (done) return;
        done = true;
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        resolve(value);
      }
      function ok() { finish(type === 'prompt' ? String(input ? input.value : '') : true); }
      function cancel() { finish(type === 'prompt' ? null : false); }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); cancel(); }
        if (e.key === 'Enter') { e.preventDefault(); ok(); }
      }
      overlay.querySelector('[data-dialog-ok]').addEventListener('click', ok);
      var cancelBtn = overlay.querySelector('[data-dialog-cancel]');
      if (cancelBtn) cancelBtn.addEventListener('click', cancel);
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
})();
