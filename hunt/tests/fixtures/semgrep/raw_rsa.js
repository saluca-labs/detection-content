const crypto = require('crypto');

function positive(key, buf) {
  const a = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_NO_PADDING }, buf); // EXPECT:raw-rsa-node-no-padding-private
  const b = crypto.privateEncrypt({ key: key, padding: crypto.constants.RSA_NO_PADDING }, buf); // EXPECT:raw-rsa-node-no-padding-private
  return [a, b];
}

function negative(key, pub, buf) {
  const c = crypto.privateDecrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf);
  const d = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_NO_PADDING }, buf);
  return [c, d];
}
