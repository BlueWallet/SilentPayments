import { ECPairFactory } from "ecpair";
import assert from "node:assert";
import { expect, it } from "vitest";
import { Stack, Transaction, script } from "bitcoinjs-lib";
import { getPubkeys, SilentPayment, UTXOType } from "../src";
import ecc from "../src/noble_ecc";
import { compareUint8Arrays, concatUint8Arrays, hexToUint8Array, uint8ArrayToHex } from "../src/uint8array-extras";
import { Vin, getUTXOType } from "../tests/utils";
import jsonInput from "./data/sending_test_vectors.json";

const ECPair = ECPairFactory(ecc);

function exactMatch(a: string[], b: string[]): boolean {
  const sortedA = a.sort();
  const sortedB = b.sort();
  return sortedA.length === sortedB.length && sortedA.every((value, index) => value === sortedB[index]);
}

function matchSubset(generated: string[], expected: string[][]): boolean {
  return expected.some((subArray) => exactMatch(generated, subArray));
}

type Given = {
  vin: Vin[];
  recipients: string[];
};

type Expected = {
  outputs: string[][];
};

type Sending = {
  given: Given;
  expected: Expected;
};

type TestCase = {
  comment: string;
  sending: Sending[];
};

const tests = jsonInput as unknown as Array<TestCase>;

it("smoke test", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(sp.createTransaction([], []), []);
});

/* Sending tests from the BIP352 test vectors */
tests.forEach((testCase, index) => {
  // Prepare the 'inputs' array
  testCase.sending.forEach((sending) => {
    const utxos = sending.given.vin.map((input) => ({
      txid: input.txid,
      vout: input.vout,
      wif: ECPair.fromPrivateKey(hexToUint8Array(input.private_key)).toWIF(),
      utxoType: getUTXOType(input) as UTXOType,
    }));
    const noEligibleUtxos = utxos.every((utxo) => utxo.utxoType === "non-eligible");

    // Prepare the 'recipients' array
    const recipients = sending.given.recipients.map((recipient) => ({
      address: recipient,
      value: 1,
    }));

    it(`Test Case: ${testCase.comment}`, () => {
      const sp = new SilentPayment();
      if (noEligibleUtxos) {
        expect(() => {
          sp.createTransaction(utxos, recipients);
        }).toThrow("No eligible UTXOs with private keys found");
      } else {
        const generated = sp.createTransaction(utxos, recipients);
        const generated_pubkeys: string[] = generated.map((obj) => SilentPayment.addressToPubkey(String(obj.address))).filter(Boolean) as string[];
        assert(matchSubset(generated_pubkeys, sending.expected.outputs));
      }
    });
  });
});

it("2 inputs - 0 SP outputs (just a passthrough)", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(
    sp.createTransaction(
      [
        {
          txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
          vout: 0,
          wif: ECPair.fromPrivateKey(hexToUint8Array("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192")).toWIF(),
          utxoType: "p2wpkh",
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          wif: ECPair.fromPrivateKey(hexToUint8Array("7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056")).toWIF(),
          utxoType: "p2wpkh",
        },
      ],
      [
        {
          address: "3FiYaHYHQTmD8n2SJxVYobDeN1uQKvzkLe",
          value: 22_333,
        },
        {
          address: "3NaQS28rzijWrmy1o5npqZAxVCJPWGd2Xn",
          // no value
        },
      ]
    ),
    [
      {
        address: "3FiYaHYHQTmD8n2SJxVYobDeN1uQKvzkLe",
        value: 22_333,
      },
      {
        address: "3NaQS28rzijWrmy1o5npqZAxVCJPWGd2Xn",
        // no value
      },
    ]
  );
});

it("2 inputs - 1 SP output, 1 legacy, 1change (should not rearrange order of inputs )", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(
    sp.createTransaction(
      [
        {
          txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
          vout: 0,
          wif: ECPair.fromPrivateKey(hexToUint8Array("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192")).toWIF(),
          utxoType: "p2wpkh",
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          wif: ECPair.fromPrivateKey(hexToUint8Array("7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056")).toWIF(),
          utxoType: "p2wpkh",
        },
      ],
      [
        {
          address: "3FiYaHYHQTmD8n2SJxVYobDeN1uQKvzkLe",
          value: 11_111,
        },
        {
          address: "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
          value: 22_222,
        },
        {
          // no address, which should be interpreted as change
          value: 33_333,
        },
      ]
    ),
    [
      {
        address: "3FiYaHYHQTmD8n2SJxVYobDeN1uQKvzkLe",
        value: 11_111,
      },
      {
        address: "bc1pszgngkje7t5j3mvdw8xc5l3q7n28awdwl8pena6hrvxgg83lnpmsme6u6j", // unwrapped from SP
        value: 22_222,
      },
      {
        // no address, which should be interpreted as change
        value: 33_333,
      },
    ]
  );
});

it("SilentPayment._outpointHash() works", () => {
  const A = ECPair.fromWIF("L4cJGJp4haLbS46ZKMKrjt7HqVuYTSHkChykdMrni955Fs3Sb8vq").publicKey;
  assert.deepStrictEqual(
    uint8ArrayToHex(SilentPayment._outpointsHash(
      [
        {
          txid: "a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb",
          vout: 0,
          wif: "",
          utxoType: "p2wpkh",
        },
      ],
      A
    )),
    "94d5923201f2f239e4d2d5a44239e0377325a343e4c068cfd078217adc663d7c"
  );
  assert.deepStrictEqual(
    uint8ArrayToHex(SilentPayment._outpointsHash(
      [
        {
          txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
          vout: 0,
          wif: "",
          utxoType: "non-eligible",
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          wif: "",
          utxoType: "p2wpkh",
        },
      ],
      A
    )),
    "3ea0693eeb0c7e848ad7b875f1998e9ed02905e88a6f5c45f25fa187b7f073d2"
  );
});

it("SilentPayment._ser32() works", () => {
  assert.strictEqual(uint8ArrayToHex(SilentPayment._ser32(0)), "00000000");
  assert.strictEqual(uint8ArrayToHex(SilentPayment._ser32(1)), "00000001");
  assert.strictEqual(uint8ArrayToHex(SilentPayment._ser32(444)), "000001bc");
});

it("can validate payment code", () => {
  assert.ok(SilentPayment.isPaymentCodeValid("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"));
  assert.ok(SilentPayment.isPaymentCodeValid("sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn"));
  assert.ok(SilentPayment.isPaymentCodeValid("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq"));
  assert.ok(SilentPayment.isPaymentCodeValid("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n"));
  assert.ok(SilentPayment.isPaymentCodeValid("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5"));

  assert.ok(!SilentPayment.isPaymentCodeValid("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgn")); // short a few symbols
  assert.ok(!SilentPayment.isPaymentCodeValid("sp1qq")); // short a few symbols
  assert.ok(!SilentPayment.isPaymentCodeValid("garbage"));
  assert.ok(!SilentPayment.isPaymentCodeValid("sp2qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5")); // wrong prefix
  assert.ok(!SilentPayment.isPaymentCodeValid("qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv")); // no prefix
  assert.ok(!SilentPayment.isPaymentCodeValid("qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv123")); // no prefix
});

it("can turn pubkey into taproot address", () => {
  assert.strictEqual(SilentPayment.pubkeyToAddress("40ef293a8a0ebaf8b351a27d89ff4b5b3822a635e4afdca77a30170c363bafa3"), "bc1pgrhjjw52p6a03v635f7cnl6ttvuz9f34ujhaefm6xqtscd3m473szkl92g");

  expect(() => {
    SilentPayment.pubkeyToAddress("512040ef293a8a0ebaf8b351a27d89ff4b5b3822a635e4afdca77a30170c363bafa3");
  }).toThrow(/has no matching Address/);
});

it("can turn taproot address into pubkey", () => {
  assert.strictEqual(SilentPayment.addressToPubkey("bc1pgrhjjw52p6a03v635f7cnl6ttvuz9f34ujhaefm6xqtscd3m473szkl92g"), "40ef293a8a0ebaf8b351a27d89ff4b5b3822a635e4afdca77a30170c363bafa3");
});

it("can calculate tweak using getPubkeysFromTransactionInputs()", () => {
  // for indexing, you need the sum of the (eligible) input public keys (call it A), multiplied by the input_hash, i.e,
  // hash(A|smallest_outpoint). this is a public key (33bytes) so this 33 bytes per tx is sent to the client.
  // that would be a tweak (per tx)

  let tx = Transaction.fromHex(
    "02000000000101d3ab6062629aad468851b4a98ca88107331311423292f5486ed96af1c03d2bff0100000000000000800250c6020000000000160014e745fe0f6421d82c3cbd036d054df86a281847541027000000000000225120e79aeee6ece0ebf0e3d806c939c906a4d0bbda9ea85f4da1c6497f9c32a3d4a902483045022100c1cd26e4ae2279c8b0317131b471d75ab0fa78796b22649338c0e1bb8d8b43cb022046e8e72e9bb5587c36b38cf354c6062d24a0bc54803fb7f64761067e4ea649b3012103a9165e1be3be592e16925159e393a43307a4557947df998e41946dcdd2f1e79500000000"
  );
  assert.strictEqual(uint8ArrayToHex(SilentPayment.getPubkeysFromTransactionInputs(tx)[0]), "03a9165e1be3be592e16925159e393a43307a4557947df998e41946dcdd2f1e795");

  const A = sumPubKeys(SilentPayment.getPubkeysFromTransactionInputs(tx));

  // looking for smallest outpoint:
  const outpoints: Array<Uint8Array> = [];
  for (const inn of tx.ins) {
    const txidBuffer = inn.hash.reverse();
    const voutBuffer = new Uint8Array(SilentPayment._ser32(inn.index).reverse());
    outpoints.push(new Uint8Array([...txidBuffer, ...voutBuffer]));
  }
  outpoints.sort((a, b) => compareUint8Arrays(a, b));
  const smallest_outpoint = outpoints[0];
  const input_hash = SilentPayment.taggedHash("BIP0352/Inputs", concatUint8Arrays([smallest_outpoint, A]));

  // finally, computing tweak:
  const T = ecc.pointMultiply(A, input_hash);
  // TODO: add actual test vectors and verify that tweak is always calculated correctly for different txs

  ///////////////////////////////////////////////////////////////////////////////////////

  tx = Transaction.fromHex(
    "02000000000102f48fb0ce46aacab0d4aa23307c49c21603c07dba03f319e19081e6398b3e890f0000000000fdffffffdcc539465c00b20610df99da5fedc69ff8690ba7b4f055de97c4a33d3998c4b00100000000fdffffff022202000000000000225120dc5eadea373119e9900ee61e5bff6b681857ac1ed8d8b4ba032a36a3635d93a2583e0f0000000000160014923861824628261ddbe226da37935b0186bb95b10247304402207dbd0692296fd0d176bd8e60a64d6269c3abf6d36d4381434739bc6cfaef9ac0022049198fb69c45022dcf69a3adb8924a1149f562699f85e6214e5064e809d89b57012103341b7b2c152d64c879d62f3c581b02cc688b67e08406c2223a4ed12bf678414a0247304402200dd830ad23a38b96baa151db91757a605fbea6df558ad82b79e1c33ec9a0acff022056470119bd3ef6a62c7d10fe3f9985c8c8ee585da0a4e275fa52abbf94db0281012103ab0f6573cdf40b2a0582565cb5628a46af9f102d568501b20c4ac9e33927fa7500000000"
  );
  assert.strictEqual(uint8ArrayToHex(SilentPayment.getPubkeysFromTransactionInputs(tx)[0]), "03341b7b2c152d64c879d62f3c581b02cc688b67e08406c2223a4ed12bf678414a");
  assert.strictEqual(uint8ArrayToHex(SilentPayment.getPubkeysFromTransactionInputs(tx)[1]), "03ab0f6573cdf40b2a0582565cb5628a46af9f102d568501b20c4ac9e33927fa75");
});

export function sumPubKeys(pubkeys: Uint8Array[], compressed: boolean = true): Uint8Array | null {
  if (pubkeys.length === 0) return null;
  if (pubkeys.length === 1) return pubkeys[0];

  let result = pubkeys[0];
  for (let i = 1; i < pubkeys.length; i++) {
    const sum = ecc.pointAdd(result, pubkeys[i], compressed);
    if (!sum) return null;
    result = sum;
  }
  return result;
}
