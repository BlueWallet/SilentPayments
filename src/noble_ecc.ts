/**
 * ECC implementation using @bitcoinerlab/secp256k1
 * Extended with privateMultiply and getSharedSecret for Silent Payments (BIP-352).
 *
 * @see https://github.com/bitcoinerlab/secp256k1
 */
import * as ecc from "@bitcoinerlab/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils";

function privateMultiply(d: Uint8Array, tweak: Uint8Array): Uint8Array | null {
  if (!ecc.isPrivate(d)) throw new Error("Expected Private");
  try {
    const result = numberToBytesBE(mod(bytesToNumberBE(d) * bytesToNumberBE(tweak), secp256k1.CURVE.n), 32);
    return secp256k1.utils.isValidSecretKey(result) ? result : null;
  } catch {
    return null;
  }
}

export default {
  ...ecc,
  privateMultiply,
  getSharedSecret: (sk: Uint8Array, pk: Uint8Array, compressed = true): Uint8Array => {
    return secp256k1.getSharedSecret(sk, pk, compressed);
  },
};
