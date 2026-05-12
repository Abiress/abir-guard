const assert = require('assert');
const { AbirGuard } = require('./abir_guard');

(async () => {
  const sdk = new AbirGuard();

  const key = await sdk.generateKeyPair('agent-js');
  assert.ok(key.publicKey);

  const encrypted = await sdk.encrypt('agent-js', 'phase5-data');
  const plain = await sdk.decrypt('agent-js', encrypted);
  assert.strictEqual(plain, 'phase5-data');

  const kem = await sdk.generateMlKemKeyPair();
  const enc = await sdk.kemEncapsulate(kem.publicKey);
  const dec = await sdk.kemDecapsulate(enc.ciphertext, kem.secretKey);
  assert.ok(dec.sharedSecret);

  const dsa = await sdk.generateMlDsaKeyPair();
  const signature = await sdk.mlDsaSign('message', dsa.secretKey);
  const valid = await sdk.mlDsaVerify('message', signature.signature, dsa.publicKey);
  assert.strictEqual(valid, true);

  console.log('js_phase5_ok');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
