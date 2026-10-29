// ECC backend for tests. Default is tiny-secp256k1 (WASM), ECC_LIB=noble switches to pure JS @bitcoinerlab/secp256k1
// to make sure the lib works with any TinySecp256k1Interface implementation.
import * as tiny from "tiny-secp256k1";
import * as noble from "@bitcoinerlab/secp256k1";
import type { TinySecp256k1Interface } from "../src";

export const ecc: TinySecp256k1Interface = process.env.ECC_LIB === "noble" ? noble : tiny;
