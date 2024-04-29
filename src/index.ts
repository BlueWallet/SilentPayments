import * as crypto from "crypto";
import { ECPairFactory } from "ecpair";
import { bech32m } from "bech32";
import * as bitcoin from "bitcoinjs-lib";
import ecc from "./noble_ecc";

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

export type UTXOType = 'p2wpkh' | 'p2sh-p2wpkh' | 'p2pkh' | 'p2tr' | 'non-eligible';
type UTXO = {
  txid: string;
  vout: number;
  WIF: string;
  utxoType: UTXOType;
};

type Target = {
  silentPaymentCode?: string;
  address?: string;
  value?: number;
};

type SilentPaymentGroup = {
  Bscan: Buffer;
  BmValues: Array<[Buffer, number | undefined]>;
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

    const silentPaymentGroups: Array<SilentPaymentGroup> = [];
    for (const target of targets) {
      if (!target.silentPaymentCode) {
        ret.push(target); // passthrough
        continue;
      }

      const result = bech32m.decode(target.silentPaymentCode, 118);
      const version = result.words.shift();
      if (version !== 0) {
        throw new Error("Unexpected version of silent payment code");
      }
      const data = bech32m.fromWords(result.words);
      const Bscan = Buffer.from(data.slice(0, 33));
      const Bm = Buffer.from(data.slice(33));

      // Addresses with the same Bscan key all belong to the same recipient
      const recipient = silentPaymentGroups.find((group) => Buffer.compare(group.Bscan, Bscan) === 0);
      if (recipient) {
        recipient.BmValues.push([Bm, target.value]);
      } else {
        silentPaymentGroups.push({
          Bscan: Bscan,
          BmValues: [[Bm, target.value]],
        });
      }
    }
    if (silentPaymentGroups.length === 0) return ret; // passthrough

    const a = SilentPayment._sumPrivkeys(utxos);
    const outpoint_hash = SilentPayment._outpointsHash(utxos);

    // Generating Pmn for each Bm in the group
    for (const group of silentPaymentGroups) {
      // Bscan * a * outpoint_hash
      const ecdh_shared_secret_step1 = Buffer.from(ecc.privateMultiply(outpoint_hash, a) as Uint8Array);
      const ecdh_shared_secret = ecc.pointMultiply(group.Bscan, ecdh_shared_secret_step1);

      let n = 0;
      for (const [Bm, amount] of group.BmValues) {
        const tn = crypto
          .createHash("sha256")
          .update(Buffer.concat([ecdh_shared_secret!, SilentPayment._ser32(n)]))
          .digest();

        // Let Pmn = tn·G + Bm
        const Pmn = Buffer.from(ecc.pointAdd(ecc.pointMultiply(G, tn) as Uint8Array, Bm) as Uint8Array);

        // Encode Pmn as a BIP341 taproot output
        const address = Pmn.slice(1).toString("hex");
        const newTarget: Target = { address };
        newTarget.value = amount;
        ret.push(newTarget);
        n += 1;
      }
      n += 1;
    }
    return ret;
  }

  static _outpointsHash(parameters: UTXO[]): Buffer {
    let bufferConcat = Buffer.alloc(0);
    const outpoints: Array<Buffer> = [];
    for (const parameter of parameters) {
      outpoints.push(Buffer.concat([Buffer.from(parameter.txid, "hex").reverse(), SilentPayment._ser32(parameter.vout).reverse()]));
    }
    outpoints.sort(Buffer.compare);
    for (const outpoint of outpoints) {
      bufferConcat = Buffer.concat([bufferConcat, outpoint]);
    }
    return crypto.createHash("sha256").update(bufferConcat).digest();
  }

  /**
   * Serializes a 32-bit unsigned integer i as a 4-byte big-endian
   * @param i {number} The number to serialize
   * @returns {Buffer} The serialized number
   * @private
   * */
  static _ser32(i: number): Buffer {
    const returnValue = Buffer.allocUnsafe(4);
    returnValue.writeUInt32BE(i);
    return returnValue;
  }

  /**
   * Sums the private keys of the UTXOs
   * @param utxos {UTXO[]}
   * @returns {Buffer} The sum of the private keys
   * @private
   **/
  private static _sumPrivkeys(utxos: UTXO[]): Buffer {
    if (utxos.length === 0) {
      throw new Error("No UTXOs provided");
    }

    const keys: Array<Buffer> = []
    for (const utxo of utxos) {
      let key = ECPair.fromWIF(utxo.WIF).privateKey;
      switch (utxo.utxoType) {
        case 'non-eligible':
            // Non-eligible UTXOs can be spent in the transaction, but are not used for the
            // shared secret derivation. Note: we don't check that the private key is valid
            // for non-eligible utxos because its possible the sender is following a different
            // signing protocol for these utxos. For silent payments eligible utxos, we require
            // access to the private key.
            break;
        case 'p2tr':
          if (key === undefined) {
            throw new Error("No private key found for eligible UTXO");
          }

          // For taproot, check if the seckey results in an odd y-value and negate if so
          if (ecc.pointFromScalar(key)![0] === 0x03) {
            key = Buffer.from(ecc.privateNegate(key));
          }
        case 'p2wpkh':
        case 'p2sh-p2wpkh':
        case 'p2pkh':
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
      return Buffer.from(ecc.privateAdd(acc, key) as Uint8Array);
    });

    return ret
  }
}
