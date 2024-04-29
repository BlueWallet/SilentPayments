import { UTXOType } from "../src";
import * as crypto from 'crypto';
import { Buffer } from 'buffer';

// The following utilities are provided to determine the UTXOType of a transaction input.
// This is necessary for parsing the test vectors from BIP352, but in practice a sending
// wallet will already know the UTXOType for each UTXO it indends to spend and can set the
// UTXOType field directly.
//
// For example, if the sending wallet only supports native segwit, all UTXOs it spends will
// be UTXOType = 'p2wpkh'.
//
// For receiving, these functions are also not necessary in practice as it is assumed any
// light client wallet is getting the 33 bytes of input public data from a full node that has
// already done the transaction parsing and determined which inputs are eligible and which are not.
class BufferReader {
    private b: Buffer;
    private offset: number;

    constructor(b: Buffer) {
        this.b = b;
        this.offset = 0;
    }

    readUInt64LE() {
      const a = this.b.readUInt32LE(this.offset);
      let b = this.b.readUInt32LE(this.offset + 4);
      b *= 0x100000000;
      return b + a;
    }

    readCompactSize(): number {
        if (this.b.length === 0) {
            return 0; // end of stream
        }
        let nit: number;
        const firstByte = this.b.readUInt8(this.offset);
        this.offset += 1;
        if (firstByte === 0xfd) {
            nit = this.b.readUInt16LE(this.offset);
            this.offset += 2;
        } else if (firstByte === 0xfe) {
            nit = this.b.readUInt32LE(this.offset);
            this.offset += 4;
        } else if (firstByte === 0xff) {
            nit = this.readUInt64LE();
            this.offset += 8;
        } else {
            nit = firstByte;
        }
        return nit;
    }

    readElement(): Buffer {
        const nit = this.readCompactSize();
        return this.b.slice(this.offset, this.offset + nit);
    }

    public readVector(): Buffer[] {
        const nit = this.readCompactSize();
        const r: Buffer[] = [];
        for (let i = 0; i < nit; i++) {
            const t = this.readElement();
            r.push(t);
            this.offset += t.length;
        }
        return r;
    }
}

const NUMS_H = Buffer.from('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex');

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

function hash160(s: Buffer): Buffer {
    const sha256Digest = crypto.createHash('sha256').update(s).digest();
    const ripemd160Digest = crypto.createHash('ripemd160').update(sha256Digest).digest();
    return ripemd160Digest;
}

function isP2tr(spk: Buffer): boolean {
    if (spk.length !== 34) {
        return false;
    }
    // OP_1 OP_PUSHBYTES_32 <32 bytes>
    return spk[0] === 0x51 && spk[1] === 0x20;
}

function isP2wpkh(spk: Buffer): boolean {
    if (spk.length !== 22) {
        return false;
    }
    // OP_0 OP_PUSHBYTES_20 <20 bytes>
    return spk[0] === 0x00 && spk[1] === 0x14;
}

function isP2sh(spk: Buffer): boolean {
    if (spk.length !== 23) {
        return false;
    }
    // OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return spk[0] === 0xA9 && spk[1] === 0x14 && spk[spk.length - 1] === 0x87;
}

function isP2pkh(spk: Buffer): boolean {
    if (spk.length !== 25) {
        return false;
    }
    // OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return spk[0] === 0x76 && spk[1] === 0xA9 && spk[2] === 0x14 && spk[spk.length - 2] === 0x88 && spk[spk.length - 1] === 0xAC;
}

export function getUTXOType(vin: Vin): UTXOType {
    const spk = Buffer.from(vin.prevout.scriptPubKey.hex, "hex");
    if (isP2pkh(spk)) {
        // skip the first 3 op_codes and grab the 20 byte hash
        // from the scriptPubKey
        const spkHash = spk.slice(3, 3 + 20);
        const scriptSig = Buffer.from(vin.scriptSig, "hex");
        for (let i = scriptSig.length; i > 0; i--) {
            if (i - 33 >= 0) {
                // starting from the back, we move over the scriptSig with a 33 byte
                // window (to match a compressed pubkey). we hash this and check if it matches
                // the 20 byte has from the scriptPubKey. for standard scriptSigs, this will match
                // right away because the pubkey is the last item in the scriptSig.
                // if its a non-standard (malleated) scriptSig, we will still find the pubkey if its
                // a compressed pubkey.
                //
                // note: this is an incredibly inefficient implementation, for demonstration purposes only.
                const pubkeyBytes = scriptSig.slice(i - 33, i);
                const pubkeyHash = hash160(pubkeyBytes);
                if (pubkeyHash.equals(spkHash)) {
                    return 'p2pkh';
                }
            }
        }
    }
    if (isP2sh(spk)) {
        const redeemScript = Buffer.from(vin.scriptSig, "hex").slice(1);
        if (isP2wpkh(redeemScript)) {
            const br = new BufferReader(Buffer.from(vin.txinwitness, "hex"));
            const witnessStack = br.readVector();
            if (witnessStack[1].length === 33) {
                return 'p2wpkh';
            }
        }
    }
    if (isP2wpkh(spk)) {
        const br = new BufferReader(Buffer.from(vin.txinwitness, "hex"));
        const witnessStack = br.readVector();
        if (witnessStack[1].length === 33) {
            return 'p2wpkh';
        }
    }
    if (isP2tr(spk)) {
        const br = new BufferReader(Buffer.from(vin.txinwitness, "hex"));
        const witnessStack = br.readVector();
        if (witnessStack.length >= 1) {
            if (witnessStack.length > 1 && witnessStack[witnessStack.length - 1][0] === 0x50) {
                // Last item is annex
                witnessStack.pop();
            }
            if (witnessStack.length > 1) {
                // Script-path spend
                const controlBlock = witnessStack[witnessStack.length - 1];
                //  control block is <control byte> <32 byte internal key> and 0 or more <32 byte hash>
                const internalKey = controlBlock.slice(1, 33);
                if (internalKey.equals(NUMS_H)) {
                    // Skip if NUMS_H
                    return 'non-eligible';
                }
            }
            return 'p2tr';
        }
    }
    return 'non-eligible';
}

