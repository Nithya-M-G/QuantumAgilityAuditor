const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Ephemeral key agreement for the websocket channel.
function negotiate(peerKey) {
  const kex = crypto.createECDH('secp384r1');
  kex.generateKeys();
  return kex.computeSecret(peerKey);
}

function issueServiceToken(claims, ecPrivateKey) {
  return jwt.sign(claims, ecPrivateKey, { algorithm: 'ES256' });
}

function encryptPayload(data, key, iv) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Legacy partner integration - they cannot accept anything stronger.
function legacyPartnerCipher(data, key, iv) {
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function etag(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

// Hard negative: encoding, not encryption.
function pack(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64');
}

module.exports = { negotiate, issueServiceToken, encryptPayload,
                   legacyPartnerCipher, etag, pack };
