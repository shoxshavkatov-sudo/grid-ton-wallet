import test from 'node:test';
import assert from 'node:assert/strict';
import { mnemonicNew, mnemonicValidate, mnemonicToPrivateKey } from '@ton/crypto';
import { WalletContractV4 } from '@ton/ton';

test('mnemonic: 24 words, valid, deterministic address', async () => {
  const words = await mnemonicNew();
  assert.equal(words.length, 24);
  assert.ok(await mnemonicValidate(words));

  const kp = await mnemonicToPrivateKey(words);
  const kp2 = await mnemonicToPrivateKey(words);
  assert.deepEqual(kp, kp2, 'same seed → same keypair');

  const c = WalletContractV4.create({ workchain: 0, publicKey: kp.publicKey });
  const addr = c.address.toString({ urlSafe: true, bounceable: false });
  assert.match(addr, /^UQ[0-9A-Za-z_-]{46}$/);
});

test('different seeds → different addresses', async () => {
  const a = await mnemonicToPrivateKey(await mnemonicNew());
  const b = await mnemonicToPrivateKey(await mnemonicNew());
  assert.notEqual(
    WalletContractV4.create({ workchain: 0, publicKey: a.publicKey }).address.toString(),
    WalletContractV4.create({ workchain: 0, publicKey: b.publicKey }).address.toString());
});
