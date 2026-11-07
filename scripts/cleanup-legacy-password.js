/**
 * 一次性清理脚本：删除用户记录里遗留的 encryptedPassword 字段。
 *
 * 背景：旧版本会把密码用 AES 可逆加密后存一份，供后台"查看密码"。
 * 该功能已删除，但历史数据里的密文仍然存在，等于把明文密码的等价物留在 Redis。
 * 上线修复版后执行一次本脚本即可彻底清除（建议在低峰期运行）。
 *
 * 用法（项目根目录）：
 *   node scripts/cleanup-legacy-password.js
 */
require('dotenv').config();
const { kvGet, kvPut } = require('../redis');

(async () => {
  const users = (await kvGet('users')) || {};
  let cleaned = 0;
  for (const [name, record] of Object.entries(users)) {
    if (record && Object.prototype.hasOwnProperty.call(record, 'encryptedPassword')) {
      delete record.encryptedPassword;
      cleaned++;
    }
  }
  if (cleaned > 0) {
    await kvPut('users', users);
    console.log(`清理完成：${cleaned} 个用户记录已移除 encryptedPassword`);
  } else {
    console.log('没有需要清理的记录（历史密文已清空）');
  }
  process.exit(0);
})().catch((err) => {
  console.error('清理失败：', err);
  process.exit(1);
});
