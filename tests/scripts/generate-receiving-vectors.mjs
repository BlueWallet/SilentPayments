#!/usr/bin/env node
/**
 * Port BIP-352 receiving vectors into tests/data/receiving_test_vectors.json
 * shaped for our Transaction + prevoutScripts + tweak/detection APIs.
 *
 * Source: tests/data/send_and_receive_test_vectors.json (official BIP-352 vectors)
 * Output: tests/data/receiving_test_vectors.json (committed; CI tests against this file)
 *
 * When to run:
 * - After syncing/updating send_and_receive_test_vectors.json from the BIP repo
 * - After changing this script's output shape or skip rules
 * - After changing how receiving tests consume the generated vectors
 *
 * Do NOT run on every dev session or in CI — regenerate only when inputs or
 * porting logic change, then commit the updated receiving_test_vectors.json.
 *
 * Usage: npm run generate:receiving-vectors
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as ecc from "tiny-secp256k1";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "../..");
const sourcePath = path.join(root, "tests/data/send_and_receive_test_vectors.json");
const outPath = path.join(root, "tests/data/receiving_test_vectors.json");

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function readUInt32LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
}

function readUInt16LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

class BufferReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }

  readUInt64LE() {
    const lo = readUInt32LE(this.bytes, this.offset);
    const hi = readUInt32LE(this.bytes, this.offset + 4);
    this.offset += 8;
    return hi * 0x100000000 + lo;
  }

  readCompactSize() {
    if (this.bytes.length === 0 || this.offset >= this.bytes.length) {
      return 0;
    }
    const first = this.bytes[this.offset++];
    if (first === 0xfd) {
      const value = readUInt16LE(this.bytes, this.offset);
      this.offset += 2;
      return value;
    }
    if (first === 0xfe) {
      const value = readUInt32LE(this.bytes, this.offset);
      this.offset += 4;
      return value;
    }
    if (first === 0xff) {
      return this.readUInt64LE();
    }
    return first;
  }

  readElement() {
    const size = this.readCompactSize();
    const element = this.bytes.slice(this.offset, this.offset + size);
    this.offset += size;
    return element;
  }

  readVector() {
    const count = this.readCompactSize();
    const items = [];
    for (let i = 0; i < count; i++) {
      items.push(this.readElement());
    }
    return items;
  }
}

function witnessFromHex(txinwitness) {
  if (!txinwitness) {
    return [];
  }
  const reader = new BufferReader(hexToBytes(txinwitness));
  return reader.readVector().map((item) => bytesToHex(item));
}

function spendPubkeyHex(spendPrivKeyHex) {
  const point = ecc.pointFromScalar(hexToBytes(spendPrivKeyHex), true);
  if (!point) {
    throw new Error(`invalid spend privkey ${spendPrivKeyHex}`);
  }
  return bytesToHex(point);
}

function toApiInputs(vins) {
  return vins.map((vin) => ({
    txid: vin.txid,
    vout: vin.vout,
    scriptSig: vin.scriptSig,
    witness: witnessFromHex(vin.txinwitness),
    prevoutScript: vin.prevout.scriptPubKey.hex,
  }));
}

function toOutputScripts(xonlyPubkeys) {
  return xonlyPubkeys.map((pubkey) => "5120" + pubkey);
}

const source = JSON.parse(fs.readFileSync(sourcePath, "utf8"));
const vectors = [];

for (const testCase of source) {
  const receiving = testCase.receiving?.[0];
  if (!receiving) {
    continue;
  }

  const { given, expected } = receiving;
  const labels = given.labels ?? [];
  const skip = labels.length > 0;
  const outputPubKeys = given.outputs ?? [];

  let foundPubKeys = [];
  if ("outputs" in expected && Array.isArray(expected.outputs)) {
    foundPubKeys = expected.outputs.map((entry) => entry.pub_key).sort();
  }

  const entry = {
    comment: testCase.comment,
    skip,
    ...(skip ? { skipReason: "labels not implemented yet" } : {}),
    inputs: toApiInputs(given.vin),
    outputPubKeys: skip ? [] : outputPubKeys,
    txOutputScripts: skip ? [] : toOutputScripts(outputPubKeys),
    bscan: given.key_material.scan_priv_key,
    Bspend: spendPubkeyHex(given.key_material.spend_priv_key),
    expected: {
      tweak: expected.tweak ?? null,
      shared_secret: expected.shared_secret ?? null,
      input_pub_key_sum: expected.input_pub_key_sum ?? null,
      found_pub_keys: foundPubKeys,
      ...(expected.n_outputs !== undefined ? { found_count: expected.n_outputs } : {}),
    },
  };

  vectors.push(entry);
}

fs.writeFileSync(outPath, JSON.stringify(vectors, null, 2) + "\n");

const active = vectors.filter((vector) => !vector.skip).length;
const skipped = vectors.length - active;
console.log(`Wrote ${vectors.length} receiving vectors to ${outPath} (${active} active, ${skipped} skipped)`);
