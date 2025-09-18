const crypto = require('crypto');
const bcrypt = require('bcrypt');

const APP_SECRET = process.env.APP_SECRET || 'dev-only-change-me'; // MUST set in prod
const AES_KEY = crypto.createHash('sha256').update(APP_SECRET).digest(); // 32 bytes

function encryptSecret(plainBase32) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const enc = Buffer.concat([cipher.update(plainBase32, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    secretEnc: enc.toString('base64'),
    secretIv: iv.toString('base64'),
    secretTag: tag.toString('base64'),
  };
}

function decryptSecret({ secretEnc, secretIv, secretTag }) {
  const iv = Buffer.from(secretIv, 'base64');
  const tag = Buffer.from(secretTag, 'base64');
  const enc = Buffer.from(secretEnc, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}

// 10 one-time recovery codes like: XXXX-XXXX (store hashed)
function generateRecoveryCodes(n = 10) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    const raw = crypto.randomBytes(4).toString('hex').slice(0,8).toUpperCase(); // 8 hex chars
    const pretty = `${raw.slice(0,4)}-${raw.slice(4)}`;
    codes.push(pretty);
  }
  return codes;
}

async function hashRecoveryCodes(codes) {
  const hashed = [];
  for (const code of codes) {
    hashed.push(await bcrypt.hash(code, 10));
  }
  return hashed;
}

async function verifyRecoveryCode(code, hashedCodes) {
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(code, hashedCodes[i])) {
      // single-use: caller should remove this index from DB
      return i; // return index matched
    }
  }
  return -1;
}

module.exports = {
  encryptSecret,
  decryptSecret,
  generateRecoveryCodes,
  hashRecoveryCodes,
  verifyRecoveryCode,
};
