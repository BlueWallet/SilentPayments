// @ts-ignore runtime built-in (Node/Bun)
import * as crypto from "crypto";
import { ECPairFactory } from "ecpair";
import { bech32m } from "bech32";
import * as bitcoin from "bitcoinjs-lib";
import { Transaction } from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as bip39 from "bip39";

import * as ecc from "tiny-secp256k1";
import { getEligiblePubkeyFromInput, isValidScalar, type SilentPaymentInputType } from "./input-pubkeys";
import { areUint8ArraysEqual, compareUint8Arrays, concatUint8Arrays, hexToUint8Array, uint8ArrayToHex } from "./uint8array-extras";

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

export type UTXOType = SilentPaymentInputType;

export type UTXO = {
  txid: string;
  vout: number;
  wif: string;
  utxoType: UTXOType;
};

export type Target = {
  address?: string; // either address or payment code
  value?: number;
};

export type SilentPaymentGroup = {
  Bscan: Uint8Array;
  BmValues: Array<[Uint8Array, number | undefined, number]>;
};

/** Per-group recipient limit defined by BIP-352. */
export const K_MAX = 2323;

export const G = hexToUint8Array("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

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
    const ret: Target[] = new Array(targets.length);

    const silentPaymentGroups: Array<SilentPaymentGroup> = [];
    for (let i = 0; i < targets.length; i++) {
      const target = targets[i];
      if (!target.address?.startsWith("sp1")) {
        ret[i] = target; // passthrough
        continue;
      }

      const result = bech32m.decode(target.address, 118);
      const version = result.words.shift();
      if (version !== 0) {
        throw new Error("Unexpected version of silent payment code");
      }
      const data = bech32m.fromWords(result.words);
      const Bscan = new Uint8Array(data.slice(0, 33));
      const Bm = new Uint8Array(data.slice(33));

      // Addresses with the same Bscan key all belong to the same recipient
      const recipient = silentPaymentGroups.find((group) => compareUint8Arrays(group.Bscan, Bscan) === 0);
      if (recipient) {
        recipient.BmValues.push([Bm, target.value, i]);
      } else {
        silentPaymentGroups.push({
          Bscan: Bscan,
          BmValues: [[Bm, target.value, i]],
        });
      }
    }
    if (silentPaymentGroups.length === 0) return ret; // passthrough

    if (silentPaymentGroups.some((group) => group.BmValues.length > K_MAX)) {
      throw new Error(`Silent payment elements for a single recipient group exceed the limit of ${K_MAX}`);
    }

    const a = SilentPayment._sumPrivkeys(utxos);
    const A = new Uint8Array(ecc.pointFromScalar(a) as Uint8Array);
    const outpoint_hash = SilentPayment._outpointsHash(utxos, A);
    if (!isValidScalar(outpoint_hash)) {
      throw new Error("Invalid input hash");
    }

    // Generating Pmk for each Bm in the group
    for (const group of silentPaymentGroups) {
      // Bscan * a * outpoint_hash
      const ecdh_shared_secret_step1 = SilentPayment._privateMultiply(outpoint_hash, a);
      const ecdh_shared_secret = getSharedSecret(ecdh_shared_secret_step1, group.Bscan);

      let k = 0;
      for (const [Bm, amount, i] of group.BmValues) {
        const tk = SilentPayment._sharedSecretTweakAtK(ecdh_shared_secret, k);
        if (tk === null) {
          throw new Error("Invalid shared secret tweak");
        }

        const outputXonly = SilentPayment._expectedOutputXonlyAtK(tk, Bm);
        if (outputXonly === null) {
          throw new Error("Invalid silent payment output key");
        }

        const address = SilentPayment.pubkeyToAddress(uint8ArrayToHex(outputXonly));
        const newTarget: Target = { address };
        newTarget.value = amount;
        ret[i] = newTarget;
        k += 1;
      }
    }
    return ret;
  }

  static taggedHash(tag: "BIP0352/Inputs" | "BIP0352/SharedSecret", data: Uint8Array): Uint8Array {
    const hash = crypto.createHash("sha256");
    const tagHash = new Uint8Array(hash.update(tag, "utf-8").digest());
    const ss = concatUint8Arrays([tagHash, tagHash, data]);
    return new Uint8Array(crypto.createHash("sha256").update(ss).digest());
  }

  static _outpointsHash(parameters: UTXO[], A: Uint8Array): Uint8Array {
    const outpoints: Array<Uint8Array> = [];
    for (const parameter of parameters) {
      const txidBuffer = hexToUint8Array(parameter.txid).reverse();
      const voutBuffer = new Uint8Array(SilentPayment._ser32(parameter.vout).reverse());
      outpoints.push(new Uint8Array([...txidBuffer, ...voutBuffer]));
    }
    outpoints.sort((a, b) => compareUint8Arrays(a, b));
    const smallest_outpoint = outpoints[0];
    return SilentPayment.taggedHash("BIP0352/Inputs", concatUint8Arrays([smallest_outpoint, A]));
  }

  /**
   * Serializes a 32-bit unsigned integer i as a 4-byte big-endian
   * @param i {number} The number to serialize
   * @returns {Uint8Array} The serialized number
   * @private
   * */
  static _ser32(i: number): Uint8Array {
    const returnValue = new Uint8Array(4);
    returnValue[0] = (i >> 24) & 0xff;
    returnValue[1] = (i >> 16) & 0xff;
    returnValue[2] = (i >> 8) & 0xff;
    returnValue[3] = i & 0xff;
    return returnValue;
  }

  private static _sharedSecretTweakAtK(sharedSecret: Uint8Array, k: number): Uint8Array | null {
    const t_k = SilentPayment.taggedHash("BIP0352/SharedSecret", concatUint8Arrays([sharedSecret, SilentPayment._ser32(k)]));
    return isValidScalar(t_k) ? t_k : null;
  }

  private static _expectedOutputXonlyAtK(t_k: Uint8Array, Bm: Uint8Array): Uint8Array | null {
    const tkG = ecc.pointMultiply(G, t_k);
    if (!tkG) {
      return null;
    }

    const P_k = ecc.pointAdd(tkG, Bm);
    if (!P_k) {
      return null;
    }

    return P_k.length === 33 ? P_k.subarray(1) : P_k;
  }

  private static _privateMultiply(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== 32 || b.length !== 32) {
      throw new Error("Expected 32-byte scalars for private multiply");
    }

    const product = (bytesToBigInt(a) * bytesToBigInt(b)) % SECP256K1_N;
    if (product === BigInt(0)) {
      throw new Error("Invalid private multiply result");
    }

    return bigIntTo32Bytes(product);
  }

  /**
   * Sums the private keys of the UTXOs
   * @param utxos {UTXO[]}
   * @returns {Uint8Array} The sum of the private keys
   * @private
   **/
  private static _sumPrivkeys(utxos: UTXO[]): Uint8Array {
    if (utxos.length === 0) {
      throw new Error("No UTXOs provided");
    }

    const keys: Array<Uint8Array> = [];
    for (const utxo of utxos) {
      let key = ECPair.fromWIF(utxo.wif).privateKey!;
      switch (utxo.utxoType) {
        case "non-eligible":
          // Non-eligible UTXOs can be spent in the transaction, but are not used for the
          // shared secret derivation. Note: we don't check that the private key is valid
          // for non-eligible utxos because its possible the sender is following a different
          // signing protocol for these utxos. For silent payments eligible utxos, we require
          // access to the private key.
          break;
        case "p2tr":
          if (key === undefined) {
            throw new Error("No private key found for eligible UTXO");
          }

          // For taproot, check if the seckey results in an odd y-value and negate if so
          if (ecc.pointFromScalar(key)![0] === 0x03) {
            key = new Uint8Array(ecc.privateNegate(key));
          }
          keys.push(key);
          break;
        case "p2wpkh":
        case "p2sh-p2wpkh":
        case "p2pkh":
          if (key === undefined) {
            throw new Error("No private key found for eligible UTXO");
          }
          keys.push(key);
          break;
      }
    }

    if (keys.length === 0) {
      throw new Error("No eligible UTXOs with private keys found");
    }

    // Sum scalars left-to-right. tiny-secp256k1 privateAdd returns null for the
    // zero scalar (identity), which is a valid intermediate when keys cancel.
    let ret: Uint8Array | null = keys[0];
    for (let i = 1; i < keys.length; i++) {
      if (ret === null) {
        ret = keys[i];
        continue;
      }
      const sum = ecc.privateAdd(ret, keys[i]);
      ret = sum === null ? null : new Uint8Array(sum);
    }

    if (ret === null) {
      throw new Error("Sum of private keys is zero");
    }
    return ret;
  }

  static isPaymentCodeValid(pc: string) {
    try {
      const result = bech32m.decode(pc, 118);
      const version = result.words.shift();
      if (version !== 0) {
        return false;
      }
    } catch (_) {
      return false;
    }

    return true;
  }

  static pubkeyToAddress(hex: string): string {
    const publicKey = hexToUint8Array("5120" + hex);
    return bitcoin.address.fromOutputScript(publicKey, bitcoin.networks.bitcoin);
  }

  static addressToPubkey(address: string): string {
    return uint8ArrayToHex(bitcoin.address.toOutputScript(address).subarray(2));
  }

  /**
   * Returns eligible input pubkeys for silent payments scanning, one per input when found.
   * `prevoutScripts[i]` must be the spent output script for `tx.ins[i]`.
   */
  static getEligiblePubkeysFromTransactionInputs(tx: Transaction, prevoutScripts: Uint8Array[]): Uint8Array[] {
    if (prevoutScripts.length !== tx.ins.length) {
      throw new Error("prevoutScripts length must match transaction inputs length");
    }

    const result: Uint8Array[] = [];
    for (let i = 0; i < tx.ins.length; i++) {
      const pubkey = getEligiblePubkeyFromInput(prevoutScripts[i], tx.ins[i].script, tx.ins[i].witness);
      if (pubkey !== null) {
        result.push(pubkey);
      }
    }
    return result;
  }

  /**
   * Computes the per-transaction tweak from a spending transaction and its input prevouts.
   * Returns null when the transaction should be skipped (no eligible inputs or pubkey sum is infinity).
   */
  static computeTweakForTx(tx: Transaction, prevoutScripts: Uint8Array[]): Uint8Array | null {
    const pubkeys = SilentPayment.getEligiblePubkeysFromTransactionInputs(tx, prevoutScripts);
    if (pubkeys.length === 0) {
      return null;
    }

    const A = SilentPayment.sumPubKeys(pubkeys);
    if (A === null) {
      return null;
    }

    const outpoints: Array<Uint8Array> = [];
    for (const inn of tx.ins) {
      const txidBuffer = inn.hash;
      const voutBuffer = new Uint8Array(SilentPayment._ser32(inn.index).reverse());
      outpoints.push(new Uint8Array([...txidBuffer, ...voutBuffer]));
    }
    outpoints.sort((a, b) => compareUint8Arrays(a, b));
    const smallest_outpoint = outpoints[0];
    const input_hash = SilentPayment.taggedHash("BIP0352/Inputs", concatUint8Arrays([smallest_outpoint, A]));
    if (!isValidScalar(input_hash)) {
      return null;
    }

    const tweak = ecc.pointMultiply(A, input_hash);
    return tweak ? new Uint8Array(tweak) : null;
  }

  static sumPubKeys(pubkeys: Uint8Array[], compressed: boolean = true): Uint8Array | null {
    if (pubkeys.length === 0) return null;

    let result = pubkeys[0];
    let atIdentity = false;
    for (let i = 1; i < pubkeys.length; i++) {
      if (atIdentity) {
        result = pubkeys[i];
        atIdentity = false;
        continue;
      }
      const sum = ecc.pointAdd(result, pubkeys[i], compressed);
      if (!sum) {
        // Valid opposite points sum to infinity. Keep going; only the final
        // sum being identity is a failure. Invalid points still fail.
        if (ecc.isPoint(result) && ecc.isPoint(pubkeys[i])) {
          atIdentity = true;
          continue;
        }
        return null;
      }
      result = sum;
    }

    if (atIdentity) return null;
    if (result!.length === 32) {
      // We have an x-only point, need to determine correct parity
      // Use the pointCompress function to get the proper compressed format
      try {
        // Create a temporary compressed point by trying both parities
        // First try even parity (0x02)
        const evenPoint = concatUint8Arrays([new Uint8Array([2]), result]);
        if (ecc.isPoint(evenPoint)) {
          return ecc.pointCompress(evenPoint, compressed);
        }

        // If even doesn't work, try odd parity (0x03)
        const oddPoint = concatUint8Arrays([new Uint8Array([3]), result]);
        if (ecc.isPoint(oddPoint)) {
          return ecc.pointCompress(oddPoint, compressed);
        }

        return null;
      } catch {
        return null;
      }
    }

    return result;
  }

  /**
   * takes BIP-39 mnemonic seed and returns shareable static payment code; also: Bscan, bscan, Bspend, bspend
   */
  static seedToCode(bip39seed: string, accountNum = 0, passphrase = ""): { address: string; Bscan: Uint8Array; bscan: Uint8Array; Bspend: Uint8Array; bspend: Uint8Array } {
    const root = bip32.fromSeed(new Uint8Array(bip39.mnemonicToSeedSync(bip39seed, passphrase)));
    const scanXprv = root.derivePath(`m/352'/0'/${accountNum}'/1'/0`);
    const spendXprv = root.derivePath(`m/352'/0'/${accountNum}'/0'/0`);
    const Bscan = scanXprv.publicKey;
    const bscan = scanXprv.privateKey;
    const Bspend = spendXprv.publicKey;
    const bspend = spendXprv.privateKey;

    assert(bscan, "could not derive bscan from seed");
    assert(bspend, "could not derive bspend from seed");

    const bech32Version = 0;
    const words = [bech32Version].concat(bech32m.toWords(concatUint8Arrays([Bscan, Bspend])));
    const address = bech32m.encode("sp", words, 1023);
    return { address, Bscan, bscan, Bspend, bspend };
  }

  /**
   * takes a decoded transaction (`bitcoinjs.Transaction.fromHex()` will do fine),
   * takes computed tweak for this transaction, your mnemonic seed, and gives you UTXOs from this transaction
   * that you own. tweak is _not_ calculated here because theoretically it can come from a tweak-indexing backend
   * service.
   */
  static detectOurUtxos(tx: Transaction, seed: string, tweakHex: string) {
    const ret: UTXO[] = [];
    const code = SilentPayment.seedToCode(seed);
    const sharedSecret = getSharedSecret(code.bscan, hexToUint8Array(tweakHex));

    // todo: iterate k (aka label), cause it might be non-zero
    const k = 0;
    const t_k = SilentPayment._sharedSecretTweakAtK(sharedSecret, k);
    if (t_k === null) {
      return ret;
    }

    const outputXonly = SilentPayment._expectedOutputXonlyAtK(t_k, code.Bspend);
    if (outputXonly === null) {
      return ret;
    }

    const pubkeyHex = uint8ArrayToHex(outputXonly);

    let vout = 0;
    for (const o of tx.outs) {
      if (uint8ArrayToHex(o.script) === "5120" + pubkeyHex) {
        // match, that means this output is spendable by us;
        // alternatively, could compare addresses: SilentPayment.pubkeyToAddress(pubkeyHex) === SilentPayment.pubkeyToAddress(o.script)

        // deriving spending privkey for this utxo: d = b_spend + t_k (mod n)
        const d = ecc.privateAdd(code.bspend, t_k);
        if (!d) {
          console.log("SilentPayment: Invalid private‐key tweak addition");
          continue;
        }

        const keyPair = ECPair.fromPrivateKey(d);
        const wif = keyPair.toWIF();

        const u: UTXO = {
          txid: tx.getId(),
          vout,
          wif,
          utxoType: "p2tr",
        };

        ret.push(u);
      }
      vout++;
    }

    return ret;
  }

  static isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHex: string, tweakHex: string, bscan: string, Bspend: string) {
    const sharedSecret = getSharedSecret(hexToUint8Array(bscan), hexToUint8Array(tweakHex));

    // todo: iterate k (aka label), cause it might be non-zero
    const k = 0;
    const t_k = SilentPayment._sharedSecretTweakAtK(sharedSecret, k);
    if (t_k === null) {
      return false;
    }

    const outputXonly = SilentPayment._expectedOutputXonlyAtK(t_k, hexToUint8Array(Bspend));
    if (outputXonly === null) {
      return false;
    }

    return outputScriptHex === "5120" + uint8ArrayToHex(outputXonly);
  }

  static isOurUtxoUsingTweakbscanBspendAndOutputScriptUint8array(outputScript: Uint8Array, tweak: Uint8Array, bscan: Uint8Array, Bspend: Uint8Array) {
    const sharedSecret = getSharedSecret(bscan, tweak);

    // todo: iterate k (aka label), cause it might be non-zero
    const k = 0;
    const t_k = SilentPayment._sharedSecretTweakAtK(sharedSecret, k);
    if (t_k === null) {
      return false;
    }

    const outputXonly = SilentPayment._expectedOutputXonlyAtK(t_k, Bspend);
    if (outputXonly === null) {
      return false;
    }

    return areUint8ArraysEqual(outputScript.subarray(2), outputXonly);
  }

  static detectOurUtxosUsingTweakbscanBspend(tx: Transaction, tweakHex: string, bscan: string, Bspend: string) {
    const ret: Omit<UTXO, "wif">[] = [];

    let vout = 0;
    for (const o of tx.outs) {
      if (SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(uint8ArrayToHex(o.script), tweakHex, bscan, Bspend)) {
        const u: Omit<UTXO, "wif"> = {
          txid: tx.getId(),
          vout,
          utxoType: "p2tr",
        };

        ret.push(u);
      }
      vout++;
    }

    return ret;
  }
}

function assert(condition: any, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${uint8ArrayToHex(bytes)}`);
}

function bigIntTo32Bytes(num: bigint): Uint8Array {
  const hex = num.toString(16).padStart(64, "0");
  return hexToUint8Array(hex);
}

function getSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = ecc.pointMultiply(publicKey, privateKey, true);
  if (!shared) {
    throw new Error("Failed to derive shared secret");
  }

  return shared;
}
