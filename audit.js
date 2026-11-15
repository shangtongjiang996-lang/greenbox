'use strict';

const { kvAppend } = require('./redis');

function genAuditId() {
  return 'A' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

async function writeAudit(actor, action, target, detail, meta) {
  const item = {
    id: genAuditId(),
    actor: String(actor || 'admin').slice(0, 40),
    action: String(action || '').slice(0, 80),
    target: String(target || '').slice(0, 120),
    detail: String(detail || '').slice(0, 1000),
    meta: meta && typeof meta === 'object' ? meta : {},
    createdAt: Date.now(),
  };
  await kvAppend('audit_logs', item, 1000);
  return item;
}

module.exports = { writeAudit };
