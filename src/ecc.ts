import type { TinySecp256k1Interface as EcpairEcc } from "ecpair";
import type { TinySecp256k1Interface as Bip32Ecc } from "bip32";

/**
 * ECC backend required by SPFactory. Any tiny-secp256k1 compatible
 * implementation works (tiny-secp256k1, @bitcoinerlab/secp256k1, noble based shims).
 * Intersection of what ecpair and bip32 need plus what this lib calls directly.
 */
export type TinySecp256k1Interface = EcpairEcc &
  Bip32Ecc & {
    isPoint(p: Uint8Array): boolean;
    pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
    pointMultiply(p: Uint8Array, tweak: Uint8Array, compressed?: boolean): Uint8Array | null;
    pointAdd(pA: Uint8Array, pB: Uint8Array, compressed?: boolean): Uint8Array | null;
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    privateNegate(d: Uint8Array): Uint8Array;
  };
