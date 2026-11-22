'use strict';

const RESEND_ENDPOINT = 'https://api.resend.com/emails';

function appBaseUrl() {
  return String(process.env.APP_BASE_URL || 'https://greenboxhweb.com').replace(/\/+$/, '');
}

function fromAddress() {
  return String(process.env.RESEND_FROM || 'GreenBox <noreply@send.greenboxhweb.com>');
}

function isEmailConfigured() {
  return !!String(process.env.RESEND_API_KEY || '').trim();
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function layout(title, intro, actionText, actionUrl, footer) {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f7f2;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#1b2b22;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f3f7f2;padding:28px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:540px;background:#ffffff;border:1px solid #dbe7dc;border-radius:16px;overflow:hidden;">
<tr><td style="padding:24px 28px 8px;font-size:22px;font-weight:800;color:#16a34a;">GreenBox</td></tr>
<tr><td style="padding:4px 28px 0;font-size:20px;font-weight:800;color:#13201a;">${escapeHtml(title)}</td></tr>
<tr><td style="padding:12px 28px 0;font-size:14px;line-height:1.8;color:#52645a;">${intro}</td></tr>
<tr><td style="padding:22px 28px 8px;"><a href="${escapeHtml(actionUrl)}" style="display:inline-block;background:#16a34a;color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;padding:11px 20px;border-radius:9px;">${escapeHtml(actionText)}</a></td></tr>
<tr><td style="padding:8px 28px 0;font-size:12px;line-height:1.7;color:#7b8b80;word-break:break-all;">如果按钮无法点击，请复制这个链接到浏览器打开：<br>${escapeHtml(actionUrl)}</td></tr>
<tr><td style="padding:20px 28px 26px;font-size:12px;line-height:1.7;color:#7b8b80;border-top:1px solid #edf3ee;margin-top:18px;">${escapeHtml(footer || '如果不是你本人操作，请忽略这封邮件。')}</td></tr>
</table>
</td></tr></table></body></html>`;
}

async function sendEmail({ to, subject, html, text }) {
  const apiKey = String(process.env.RESEND_API_KEY || '').trim();
  if (!apiKey) {
    const err = new Error('邮件服务暂未配置');
    err.code = 'EMAIL_NOT_CONFIGURED';
    throw err;
  }
  const body = {
    from: fromAddress(),
    to: [to],
    subject,
    html,
    text: text || undefined,
  };
  if (process.env.RESEND_REPLY_TO) body.reply_to = process.env.RESEND_REPLY_TO;
  const res = await fetch(RESEND_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (!res.ok) {
    const err = new Error((data && (data.message || data.error)) || `邮件发送失败（HTTP ${res.status}）`);
    err.code = 'EMAIL_SEND_FAILED';
    err.status = res.status;
    err.detail = data;
    throw err;
  }
  return data;
}

module.exports = { appBaseUrl, fromAddress, isEmailConfigured, escapeHtml, layout, sendEmail };
