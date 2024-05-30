import assert from "node:assert";
import { ECPairFactory } from "ecpair";
import { SilentPayment, UTXOType } from "../src";
import ecc from "../src/noble_ecc";
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
      wif: ECPair.fromPrivateKey(Buffer.from(input.private_key, "hex")).toWIF(),
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
          wif: ECPair.fromPrivateKey(Buffer.from("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192", "hex")).toWIF(),
          utxoType: "p2wpkh",
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          wif: ECPair.fromPrivateKey(Buffer.from("7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056", "hex")).toWIF(),
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
          wif: ECPair.fromPrivateKey(Buffer.from("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192", "hex")).toWIF(),
          utxoType: "p2wpkh",
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          wif: ECPair.fromPrivateKey(Buffer.from("7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056", "hex")).toWIF(),
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
    SilentPayment._outpointsHash(
      [
        {
          txid: "a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb",
          vout: 0,
          wif: "",
          utxoType: "p2wpkh",
        },
      ],
      A
    ).toString("hex"),
    "94d5923201f2f239e4d2d5a44239e0377325a343e4c068cfd078217adc663d7c"
  );
  assert.deepStrictEqual(
    SilentPayment._outpointsHash(
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
    ).toString("hex"),
    "3ea0693eeb0c7e848ad7b875f1998e9ed02905e88a6f5c45f25fa187b7f073d2"
  );
});

it("SilentPayment._ser32() works", () => {
  assert.strictEqual(SilentPayment._ser32(0).toString("hex"), "00000000");
  assert.strictEqual(SilentPayment._ser32(1).toString("hex"), "00000001");
  assert.strictEqual(SilentPayment._ser32(444).toString("hex"), "000001bc");
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
