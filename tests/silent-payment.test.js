/* global it */

import ecc from '../noble_ecc';
import {
	deobfuscatedValueToOutputData,
	deobfuscateValue,
	keyToEventType,
	keyToObfuscationKey,
	keyToOutPoint,
	varint128Read,
} from '../util';
import {SilentPayment} from '../index';
const bitcoin = require('bitcoinjs-lib');

bitcoin.initEccLib(ecc);
const assert = require('node:assert');

it('smoke test', () => {
	const sp = new SilentPayment();
	assert.deepStrictEqual(sp.createTransaction([], []), []);
});

it('1 input - 1 SP output works', () => {
	const sp = new SilentPayment();
	assert.deepStrictEqual(sp.createTransaction([
		{
			txid: 'a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb',
			vout: 0,
			WIF: 'L4cJGJp4haLbS46ZKMKrjt7HqVuYTSHkChykdMrni955Fs3Sb8vq',
		},
	], [{
		silentPaymentCode: 'sp1qcttf6jjfamj040ucutkuzss56m0rdq9aeczlayuuxk5lt7yg0a0cdctc9aq2ekzr7pk39gf8d956u7aht9sskxmx27tm9mr5zjrxd2g6zkeep',
		value: 12_345,
	}]), [
		{
			address: 'bc1pkrwcgdrye4e2uyfjchs54nucpwa7gq66hpzr68hcpxp739mxx29smlt4hf',
			value: 12_345,
		},
	]);
});

it('SilentPayment._outpointHash() works', () => {
	assert.deepStrictEqual(SilentPayment._outpointHash(
		{
			txid: 'a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb',
			vout: 0,
			WIF: 'L4cJGJp4haLbS46ZKMKrjt7HqVuYTSHkChykdMrni955Fs3Sb8vq',
		},
	).toString('hex'),
	'dc28dfeffd23899e1ec394a601ef543fa4f29c59e8548ceeca8f3b40fef5d041',
	);
});

it('SilentPayment._ser32() works', () => {
	assert.strictEqual(SilentPayment._ser32(0).toString('hex'), '00000000');
	assert.strictEqual(SilentPayment._ser32(1).toString('hex'), '01000000');
	assert.strictEqual(SilentPayment._ser32(444).toString('hex'), 'bc010000');
});
