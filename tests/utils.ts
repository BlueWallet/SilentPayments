import { UTXOType } from "../src";
import { getSilentPaymentInputType } from "../src/input-pubkeys";
import { hexToUint8Array, readUInt16, readUInt32 } from "../src/uint8array-extras";

// Parses BIP-352 test vector vin entries into UTXOType for sender tests.
// Production senders should set utxoType directly on UTXOs they already know.
class BufferReader {
  private b: Uint8Array;
  private offset: number;

  constructor(b: Uint8Array) {
    this.b = b;
    this.offset = 0;
  }

  readUInt64LE() {
    const a = readUInt32(this.b, this.offset, true);
    let b = readUInt32(this.b, this.offset + 4, true);
    b *= 0x100000000;
    return b + a;
  }

  readCompactSize(): number {
    if (this.b.length === 0) {
      return 0; // end of stream
    }
    let nit: number;
    const firstByte = this.b[this.offset];
    this.offset += 1;
    if (firstByte === 0xfd) {
      nit = readUInt16(this.b, this.offset, true);
      this.offset += 2;
    } else if (firstByte === 0xfe) {
      nit = readUInt32(this.b, this.offset, true);
      this.offset += 4;
    } else if (firstByte === 0xff) {
      nit = this.readUInt64LE();
      this.offset += 8;
    } else {
      nit = firstByte;
    }
    return nit;
  }

  readElement(): Uint8Array {
    const nit = this.readCompactSize();
    return this.b.slice(this.offset, this.offset + nit);
  }

  public readVector(): Uint8Array[] {
    const nit = this.readCompactSize();
    const r: Uint8Array[] = [];
    for (let i = 0; i < nit; i++) {
      const t = this.readElement();
      r.push(t);
      this.offset += t.length;
    }
    return r;
  }
}

export type Vin = {
  txid: string;
  vout: number;
  scriptSig: string;
  txinwitness: string;
  prevout: {
    scriptPubKey: {
      hex: string;
    };
  };
  private_key: string;
};

function witnessFromHex(txinwitness: string): Uint8Array[] {
  if (!txinwitness) {
    return [];
  }
  const br = new BufferReader(hexToUint8Array(txinwitness));
  return br.readVector();
}

export function getUTXOType(vin: Vin): UTXOType {
  return getSilentPaymentInputType(hexToUint8Array(vin.prevout.scriptPubKey.hex), hexToUint8Array(vin.scriptSig), witnessFromHex(vin.txinwitness));
}
