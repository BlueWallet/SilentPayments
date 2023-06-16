import ecc from "./noble_ecc";

const sec = require("bcrypto").secp256k1;
const crypto = require("node:crypto");
const ECPairFactory = require("ecpair").ECPairFactory;
const { bech32m } = require("bech32");
const ECPair = ECPairFactory(ecc);
const bitcoin = require("bitcoinjs-lib");
bitcoin.initEccLib(ecc);

type UTXO = {
  txid: string;
  vout: number;
  WIF: string;
};

type Target = {
  silentPaymentCode?: string;
  address?: string;
  value?: number;
};

const G = Buffer.from("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "hex");

export class SilentPayment {
  /**
   * Takes the UTXO that the sender is going to spend in a transaction,
   * and an array of Targets which may or may not have
   * SilentPayment identifiers (destinations), and returns an array of
   * Targets which have SilentPayment identifiers unwrapped into taproot addresses.
   * If target initially already had onchain address its skipped.
   * Numeric values (if present) for targets are passed through.
   */
  createTransaction(utxos: UTXO[], targets: Target[]): Target[] {
    const ret: Target[] = [];

    for (const target of targets) {
      if (!target.silentPaymentCode) {
        ret.push(target); // passthrough
        continue;
      }

      const result = bech32m.decode(target.silentPaymentCode, 115);
      const version = result.words.shift();
      const data = bech32m.fromWords(result.words);
      const Bscan = Buffer.from(data.slice(0, 32));
      const Bm = Buffer.from(data.slice(32));

      if (version !== 0) {
        throw new Error("Unexpected version of silent payment code");
      }

      //

      /*const alice_privkey = ECPair.fromWIF(utxos[0].WIF);

      const a = alice_privkey.privateKey;
      const A = alice_privkey.publicKey;*/

      const a = SilentPayment._sumPrivkeys(utxos);

      //

      const outpoint_hash = SilentPayment._outpointsHash(utxos);
      // Let ecdh_shared_secret = outpoints_hash·a·Bscan
      const ecdh_shared_secret_step1 = sec.privateKeyTweakMul(outpoint_hash, a);
      const ecdh_shared_secret = sec.publicKeyTweakMul(Buffer.concat([Buffer.from("02", "hex"), Bscan]), ecdh_shared_secret_step1);

      // Let tn = sha256(ecdh_shared_secret) || ser32(n))

      // for n=0 ...
      const tn = crypto
        .createHash("sha256")
        .update(Buffer.concat([ecdh_shared_secret, SilentPayment._ser32(0)]))
        .digest();

      // Let Pmn = tn·G + Bm
      const Pnm = sec.publicKeyCombine([sec.publicKeyTweakMul(G, tn), Buffer.concat([Buffer.from("02", "hex"), Bm])]);

      // Encode Pmn as a BIP341 taproot output
      const address = bitcoin.payments.p2tr({ pubkey: Pnm.slice(1) }).address;

      const newTarget: Target = { address };
      if (target.value) {
        newTarget.value = target.value;
      }

      ret.push(newTarget);
    }

    return ret;
  }

  static _outpointsHash(parameters: UTXO[]): Buffer {
    let bufferConcat = Buffer.alloc(0);
    for (const parameter of parameters) {
      bufferConcat = Buffer.concat([bufferConcat, Buffer.from(parameter.txid, "hex").reverse(), SilentPayment._ser32(parameter.vout).reverse()]);
    }

    return crypto.createHash("sha256").update(bufferConcat).digest();
  }

  /**
   * Serializes a 32-bit unsigned integer i as a 4-byte little-endian
   */
  static _ser32(i: number): Buffer {
    const returnValue = Buffer.allocUnsafe(4);
    returnValue.writeUInt32LE(i);
    return returnValue.reverse();
  }

  private static _sumPrivkeys(utxos: UTXO[]): Buffer {
    let ret = ECPair.fromWIF(utxos[0].WIF).privateKey;

    for (let c = 1; c < utxos.length; c++) {
      ret = sec.privateKeyTweakAdd(ret, ECPair.fromWIF(utxos[c].WIF).privateKey);
    }

    return ret;
  }
}
