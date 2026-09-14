// @ts-ignore runtime built-in (Node/Bun)
import * as crypto from "crypto";
import { script } from "bitcoinjs-lib";
import { areUint8ArraysEqual, concatUint8Arrays, hexToUint8Array } from "./uint8array-extras";

const NUMS_H = hexToUint8Array("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

function hash160(s: Uint8Array): Uint8Array {
  const sha256Digest = new Uint8Array(crypto.createHash("sha256").update(s).digest());
  return new Uint8Array(crypto.createHash("ripemd160").update(sha256Digest).digest());
}

function isP2tr(spk: Uint8Array): boolean {
  return spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20;
}

function isP2wpkh(spk: Uint8Array): boolean {
  return spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14;
}

function isP2sh(spk: Uint8Array): boolean {
  return spk.length === 23 && spk[0] === 0xa9 && spk[1] === 0x14 && spk[spk.length - 1] === 0x87;
}

function isP2pkh(spk: Uint8Array): boolean {
  return spk.length === 25 && spk[0] === 0x76 && spk[1] === 0xa9 && spk[2] === 0x14 && spk[spk.length - 2] === 0x88 && spk[spk.length - 1] === 0xac;
}

function witnessStackFromInputWitness(witness: Uint8Array[]): Uint8Array[] {
  return witness.filter((item) => item.length > 0);
}

function pubkeyFromWitnessStack(witnessStack: Uint8Array[]): Uint8Array | null {
  if (witnessStack.length === 0) {
    return null;
  }

  const pubkeyBytes = witnessStack[witnessStack.length - 1];
  if (pubkeyBytes.length !== 33 || !script.isCanonicalPubKey(pubkeyBytes)) {
    return null;
  }

  return pubkeyBytes;
}

export type SilentPaymentInputType = "p2pkh" | "p2wpkh" | "p2sh-p2wpkh" | "p2tr" | "non-eligible";

/**
 * Extract the silent-payments-eligible pubkey for one input, per BIP-352.
 * Returns null when the input is not eligible or no pubkey can be determined.
 */
export function getEligiblePubkeyFromInput(prevoutScript: Uint8Array, scriptSig: Uint8Array, witness: Uint8Array[]): Uint8Array | null {
  const witnessStack = witnessStackFromInputWitness(witness);

  if (isP2pkh(prevoutScript)) {
    const spkHash = prevoutScript.slice(3, 23);
    for (let i = scriptSig.length; i > 0; i--) {
      if (i - 33 >= 0) {
        const pubkeyBytes = scriptSig.slice(i - 33, i);
        if (!script.isCanonicalPubKey(pubkeyBytes)) {
          continue;
        }
        const pubkeyHash = hash160(pubkeyBytes);
        if (areUint8ArraysEqual(pubkeyHash, spkHash)) {
          return pubkeyBytes;
        }
      }
    }
    return null;
  }

  if (isP2sh(prevoutScript)) {
    if (scriptSig.length <= 1) {
      return null;
    }
    const redeemScript = scriptSig.slice(1);
    if (!isP2wpkh(redeemScript)) {
      return null;
    }
    return pubkeyFromWitnessStack(witnessStack);
  }

  if (isP2wpkh(prevoutScript)) {
    return pubkeyFromWitnessStack(witnessStack);
  }

  if (isP2tr(prevoutScript)) {
    if (witnessStack.length === 0) {
      return null;
    }

    const stack = [...witnessStack];
    if (stack.length > 1 && stack[stack.length - 1][0] === 0x50) {
      stack.pop();
    }

    if (stack.length > 1) {
      const controlBlock = stack[stack.length - 1];
      if (controlBlock.length < 33) {
        return null;
      }
      const internalKey = controlBlock.slice(1, 33);
      if (areUint8ArraysEqual(internalKey, NUMS_H)) {
        return null;
      }
    }

    // Taproot output keys are x-only with even Y (BIP341).
    return concatUint8Arrays([new Uint8Array([0x02]), prevoutScript.slice(2)]);
  }

  return null;
}

/** Classify an input for silent payments (sender UTXO typing and test vector parsing). */
export function getSilentPaymentInputType(prevoutScript: Uint8Array, scriptSig: Uint8Array, witness: Uint8Array[]): SilentPaymentInputType {
  let candidate: SilentPaymentInputType = "non-eligible";
  if (isP2pkh(prevoutScript)) {
    candidate = "p2pkh";
  } else if (isP2sh(prevoutScript)) {
    candidate = "p2sh-p2wpkh";
  } else if (isP2wpkh(prevoutScript)) {
    candidate = "p2wpkh";
  } else if (isP2tr(prevoutScript)) {
    candidate = "p2tr";
  } else {
    return "non-eligible";
  }

  return getEligiblePubkeyFromInput(prevoutScript, scriptSig, witness) === null ? "non-eligible" : candidate;
}

export function isValidScalar(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) {
    return false;
  }

  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }

  const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
  return value !== 0n && value < SECP256K1_N;
}
