import * as crypto from "crypto";
import { ECPairFactory } from "ecpair";
import { bech32m } from "bech32";
import * as bitcoin from "bitcoinjs-lib";
import { Stack, Transaction, script, address, networks } from "bitcoinjs-lib";
import { BIP32Factory } from 'bip32';
import * as bip39 from 'bip39';

import ecc from "./noble_ecc";
import { compareUint8Arrays, concatUint8Arrays, hexToUint8Array, uint8ArrayToHex } from "./uint8array-extras";

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);
const bip32 = BIP32Factory(ecc);

export type UTXOType = "p2wpkh" | "p2sh-p2wpkh" | "p2pkh" | "p2tr" | "non-eligible";

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

    const a = SilentPayment._sumPrivkeys(utxos);
    const A = new Uint8Array(ecc.pointFromScalar(a) as Uint8Array);
    const outpoint_hash = SilentPayment._outpointsHash(utxos, A);

    // Generating Pmk for each Bm in the group
    for (const group of silentPaymentGroups) {
      // Bscan * a * outpoint_hash
      const ecdh_shared_secret_step1 = new Uint8Array(ecc.privateMultiply(outpoint_hash, a) as Uint8Array);
      const ecdh_shared_secret = new Uint8Array(ecc.getSharedSecret(ecdh_shared_secret_step1, group.Bscan) as Uint8Array);

      let k = 0;
      for (const [Bm, amount, i] of group.BmValues) {
        const tk = SilentPayment.taggedHash("BIP0352/SharedSecret", concatUint8Arrays([ecdh_shared_secret, SilentPayment._ser32(k)]));

        // Let Pmk = tk·G + Bm
        const Pmk = new Uint8Array(ecc.pointAdd(ecc.pointMultiply(G, tk) as Uint8Array, Bm) as Uint8Array);

        // Encode Pmk as a BIP341 taproot output
        const address = SilentPayment.pubkeyToAddress(uint8ArrayToHex(Pmk.slice(1)));
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

    // summary of every item in array
    const ret = keys.reduce((acc, key) => {
      return new Uint8Array(ecc.privateAdd(acc, key) as Uint8Array);
    });

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

  static getPubkeysFromTransactionInputs(tx: Transaction): Uint8Array[] {
    const result: Uint8Array[] = [];

    const stackToPubkeys = (stack: Stack): Uint8Array[] => {
      return stack
        .filter((elem) => typeof elem !== "number") // filtering out numbers, leaving only Uint8Array
        .filter((elem) => ecc.isXOnlyPoint(elem as Uint8Array) || script.isCanonicalPubKey(elem as Uint8Array)) as Uint8Array[];
    };

    for (const input of tx.ins) {
      const inScript = script.decompile(input.script);
      if (inScript) {
        // push any pubkeys in the scriptSig
        result.push(...stackToPubkeys(inScript));
        if (inScript.length > 1) {
          const lastItem = inScript[inScript.length - 1];
          if (typeof lastItem !== "number") {
            // If the last item is a buffer, treat as redeemScript and check if we can decompile
            // and if it has any pubkeys (it might not)
            const redeemScript = script.decompile(lastItem);
            if (redeemScript) {
              result.push(...stackToPubkeys(redeemScript));
            }
          }
        }
      }
      // Find any raw pubkeys in the witness stack
      result.push(...input.witness.filter(script.isCanonicalPubKey));
      for (const item of input.witness) {
        const maybeScript = script.decompile(item);
        if (maybeScript) {
          result.push(...stackToPubkeys(maybeScript));
        }
      }
    }
    return result;
  }

  /**
   * takes decoded bitcoin transaction and computes tweak. some transactions must be augmented with prevout data
   * so the method can successfully discover all pubkeys from inputs (example: `tx.ins[0].script = txPrevout0.outs[0].script;`)
   */
  static computeTweakForTx(tx: Transaction): Uint8Array | null {
    // you need the sum of the (eligible) input public keys (call it A), multiplied by the input_hash, i.e,
    // hash(A|smallest_outpoint). this is a public key (33bytes) so this 33 bytes per tx is sent to the client.
    // that would be a tweak (per tx)
    let A = SilentPayment.sumPubKeys(SilentPayment.getPubkeysFromTransactionInputs(tx));

    // looking for smallest outpoint:
    const outpoints: Array<Uint8Array> = [];
    for (const inn of tx.ins) {
      const txidBuffer = inn.hash;
      const voutBuffer = new Uint8Array(SilentPayment._ser32(inn.index).reverse());
      outpoints.push(new Uint8Array([...txidBuffer, ...voutBuffer]));
    }
    outpoints.sort((a, b) => compareUint8Arrays(a, b));
    const smallest_outpoint = outpoints[0];
    const input_hash = SilentPayment.taggedHash("BIP0352/Inputs", concatUint8Arrays([smallest_outpoint, A]));

    // finally, computing tweak:
    return ecc.pointMultiply(A, input_hash);
  }

  static sumPubKeys(pubkeys: Uint8Array[], compressed: boolean = true): Uint8Array | null {
    if (pubkeys.length === 0) return null;

    let result = pubkeys[0];
    for (let i = 1; i < pubkeys.length; i++) {
      const sum = ecc.pointAdd(result, pubkeys[i], compressed);
      if (!sum) return null;
      result = sum;
    }

    if (result.length === 32) {
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
  static seedToCode(bip39seed: string, accountNum = 0, passphrase = ''): { address: string; Bscan: Uint8Array; bscan: Uint8Array; Bspend: Uint8Array, bspend: Uint8Array } {
    const root = bip32.fromSeed(new Uint8Array(bip39.mnemonicToSeedSync(bip39seed, passphrase)));
    const scanXprv = root.derivePath(`m/352'/0'/${accountNum}'/1'/0`);
    const spendXprv = root.derivePath(`m/352'/0'/${accountNum}'/0'/0`);
    const Bscan = scanXprv.publicKey;
    const bscan = scanXprv.privateKey;
    const Bspend = spendXprv.publicKey;
    const bspend = spendXprv.privateKey;

    const bech32Version = 0;
    const words = [bech32Version].concat(bech32m.toWords(concatUint8Arrays([Bscan, Bspend])));
    const address = bech32m.encode('sp', words, 1023);
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
    const sharedSecret = ecc.getSharedSecret(code.bscan, hexToUint8Array(tweakHex));

    // todo: iterate k (aka label), cause it might be non-zero
    const k = 0;
    const t_k = SilentPayment.taggedHash("BIP0352/SharedSecret", concatUint8Arrays([sharedSecret, SilentPayment._ser32(k)]));

    // Compute the expected output pubkey
    const P_k = ecc.pointAdd(ecc.pointMultiply(G, t_k), code.Bspend);

    let pubkeyHex = uint8ArrayToHex(P_k);
    if (pubkeyHex.startsWith("02") || pubkeyHex.startsWith("03")) pubkeyHex = pubkeyHex.substring(2);

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
          utxoType: "p2tr"
        }

        ret.push(u);
      }
      vout++;
    }

    return ret;
  }
}
