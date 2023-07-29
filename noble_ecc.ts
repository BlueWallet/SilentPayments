/**
 * adapted from https://github.com/BitGo/BitGoJS/blob/bitcoinjs_lib_6_sync/modules/utxo-lib/src/noble_ecc.ts
 * license: Apache License
 *
 * @see https://github.com/bitcoinjs/tiny-secp256k1/issues/84#issuecomment-1185682315
 * @see https://github.com/bitcoinjs/bitcoinjs-lib/issues/1781
 */
import createHash from "create-hash";
import { createHmac } from "crypto";
import * as necc from "@noble/secp256k1";
import { TinySecp256k1Interface } from "ecpair/src/ecpair";
import { TinySecp256k1Interface as TinySecp256k1InterfaceBIP32 } from "bip32/types/bip32";
import { XOnlyPointAddTweakResult } from "bitcoinjs-lib/src/types";

export interface TinySecp256k1InterfaceExtended {
  pointMultiply(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
  privateMultiply(p: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  privateNegate(d: Uint8Array): Uint8Array;

  pointAdd(pA: Uint8Array, pB: Uint8Array, compressed?: boolean): Uint8Array | null;

  isXOnlyPoint(p: Uint8Array): boolean;

  xOnlyPointAddTweak(p: Uint8Array, tweak: Uint8Array): XOnlyPointAddTweakResult | null;
}

necc.utils.sha256Sync = (...messages: Uint8Array[]): Uint8Array => {
  const sha256 = createHash("sha256");
  for (const message of messages) sha256.update(message);
  return sha256.digest();
};

necc.utils.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]): Uint8Array => {
  const hash = createHmac("sha256", Buffer.from(key));
  messages.forEach((m) => hash.update(m));
  return Uint8Array.from(hash.digest());
};

const defaultTrue = (param?: boolean): boolean => param !== false;

function throwToNull<Type>(fn: () => Type): Type | null {
  try {
    return fn();
  } catch (e) {
    // console.log(e);
    return null;
  }
}

function isPoint(p: Uint8Array, xOnly: boolean): boolean {
  if ((p.length === 32) !== xOnly) return false;
  try {
    return !!necc.Point.fromHex(p);
  } catch (e) {
    return false;
  }
}

const ecc: TinySecp256k1InterfaceExtended & TinySecp256k1Interface & TinySecp256k1InterfaceBIP32 = {
  isPoint: (p: Uint8Array): boolean => isPoint(p, false),
  isPrivate: (d: Uint8Array): boolean => {
    /* if (
      [
        '0000000000000000000000000000000000000000000000000000000000000000',
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142',
      ].includes(d.toString('hex'))
    ) {
      return false;
    } */
    return necc.utils.isValidPrivateKey(d);
  },
  isXOnlyPoint: (p: Uint8Array): boolean => isPoint(p, true),

  xOnlyPointAddTweak: (p: Uint8Array, tweak: Uint8Array): { parity: 0 | 1; xOnlyPubkey: Uint8Array } | null =>
    throwToNull(() => {
      const P = necc.utils.pointAddScalar(p, tweak, true);
      const parity = P[0] % 2 === 1 ? 1 : 0;
      return { parity, xOnlyPubkey: P.slice(1) };
    }),

  pointFromScalar: (sk: Uint8Array, compressed?: boolean): Uint8Array | null => throwToNull(() => necc.getPublicKey(sk, defaultTrue(compressed))),

  pointCompress: (p: Uint8Array, compressed?: boolean): Uint8Array => {
    return necc.Point.fromHex(p).toRawBytes(defaultTrue(compressed));
  },

  pointMultiply: (a: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null => throwToNull(() => necc.utils.pointMultiply(a, tweak, defaultTrue(compressed))),

  pointAdd: (a: Uint8Array, b: Uint8Array, compressed?: boolean): Uint8Array | null =>
    throwToNull(() => {
      const A = necc.Point.fromHex(a);
      const B = necc.Point.fromHex(b);
      return A.add(B).toRawBytes(defaultTrue(compressed));
    }),

  pointAddScalar: (p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null => throwToNull(() => necc.utils.pointAddScalar(p, tweak, defaultTrue(compressed))),

  privateAdd: (d: Uint8Array, tweak: Uint8Array): Uint8Array | null =>
    throwToNull(() => {
      // console.log({ d, tweak });
      const ret = necc.utils.privateAdd(d, tweak);
      // console.log(ret);
      if (ret.join("") === "00000000000000000000000000000000") {
        return null;
      }
      return ret;
    }),

  privateNegate: (d: Uint8Array): Uint8Array => necc.utils.privateNegate(d),

  sign: (h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array => {
    return necc.signSync(h, d, { der: false, extraEntropy: e });
  },

  signSchnorr: (h: Uint8Array, d: Uint8Array, e: Uint8Array = Buffer.alloc(32, 0x00)): Uint8Array => {
    return necc.schnorr.signSync(h, d, e);
  },

  verify: (h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict?: boolean): boolean => {
    return necc.verify(signature, h, Q, { strict });
  },

  verifySchnorr: (h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean => {
    return necc.schnorr.verifySync(signature, h, Q);
  },

  privateMultiply: (d: Uint8Array, tweak: Uint8Array) => {
    if (ecc.isPrivate(d) === false) {
      throw new Error("Expected Private");
    }

    const _privateMultiply = (privateKey: Uint8Array, tweak: Uint8Array) => {
      const p = normalizePrivateKey(privateKey);
      const t = normalizeScalar(tweak);
      const mul = _bigintTo32Bytes(necc.utils.mod(p * t, necc.CURVE.n));
      if (necc.utils.isValidPrivateKey(mul)) return mul;
      else return null;
    };

    return throwToNull(() => _privateMultiply(d, tweak));
  },
};

export default ecc;

// module.exports.ecc = ecc;

function normalizeScalar(scalar: any) {
  let num;
  if (typeof scalar === "bigint") {
    num = scalar;
  } else if (typeof scalar === "number" && Number.isSafeInteger(scalar) && scalar >= 0) {
    num = BigInt(scalar);
  } else if (typeof scalar === "string") {
    if (scalar.length !== 64) throw new Error("Expected 32 bytes of private scalar");
    num = hexToNumber(scalar);
  } else if (scalar instanceof Uint8Array) {
    if (scalar.length !== 32) throw new Error("Expected 32 bytes of private scalar");
    num = bytesToNumber(scalar);
  } else {
    throw new TypeError("Expected valid private scalar");
  }
  if (num < 0) throw new Error("Expected private scalar >= 0");
  return num;
}

function hexToNumber(hex: string) {
  return BigInt(`0x${hex}`);
}

function bytesToNumber(bytes: Uint8Array) {
  return hexToNumber(necc.utils.bytesToHex(bytes));
}

type Hex = Uint8Array | string;
type PrivKey = Hex | bigint | number;
function normalizePrivateKey(key: PrivKey): bigint {
  let num: bigint;
  if (typeof key === "bigint") {
    num = key;
  } else if (typeof key === "number" && Number.isSafeInteger(key) && key > 0) {
    num = BigInt(key);
  } else if (typeof key === "string") {
    if (key.length !== 64) throw new Error("Expected 32 bytes of private key");
    num = hexToNumber(key);
  } else if (isUint8a(key)) {
    if (key.length !== 32) throw new Error("Expected 32 bytes of private key");
    num = bytesToNumber(key);
  } else {
    throw new TypeError("Expected valid private key");
  }
  if (!isWithinCurveOrder(num)) throw new Error("Expected private key: 0 < key < n");
  return num;
}

// We can't do `instanceof Uint8Array` because it's unreliable between Web Workers etc
function isUint8a(bytes: Uint8Array | unknown): bytes is Uint8Array {
  return bytes instanceof Uint8Array;
}

function isWithinCurveOrder(num: bigint): boolean {
  return _0n < num && num < CURVE.n;
}

// Be friendly to bad ECMAScript parsers by not using bigint literals like 123n
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);

// @ts-ignore
const POW_2_256 = _2n ** BigInt(256);

const CURVE = {
  // Params: a, b
  a: _0n,
  b: BigInt(7),
  // Field over which we'll do calculations
  // @ts-ignore
  P: POW_2_256 - _2n ** BigInt(32) - BigInt(977),
  // Curve order, a number of valid points in the field
  n: POW_2_256 - BigInt("432420386565659656852420866394968145599"),
  // Cofactor. It's 1, so other subgroups don't exist, and default subgroup is prime-order
  h: _1n,
  // Base point (x, y) aka generator point
  Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
  Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"),
  // For endomorphism, see below
  beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
};

function _bigintTo32Bytes(num: bigint): Uint8Array {
  const b = hexToBytes(numTo32bStr(num));
  if (b.length !== 32) throw new Error("Error: expected 32 bytes");
  return b;
}

function numTo32bStr(num: bigint): string {
  if (typeof num !== "bigint") throw new Error("Expected bigint");
  if (!(_0n <= num && num < POW_2_256)) throw new Error("Expected number 0 <= n < 2^256");
  return num.toString(16).padStart(64, "0");
}

// Caching slows it down 2-3x
function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new TypeError("hexToBytes: expected string, got " + typeof hex);
  }
  if (hex.length % 2) throw new Error("hexToBytes: received invalid unpadded hex" + hex.length);
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error("Invalid byte sequence");
    array[i] = byte;
  }
  return array;
}
