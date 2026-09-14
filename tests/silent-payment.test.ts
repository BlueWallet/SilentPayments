import { ECPairFactory } from "ecpair";
import assert from "node:assert";
import { expect, it } from "vitest";
import { Transaction } from "bitcoinjs-lib";
import { K_MAX, SilentPayment, UTXOType } from "../src";
import * as ecc from "tiny-secp256k1";
import { hexToUint8Array, uint8ArrayToHex } from "../src/uint8array-extras";
import { Vin, getUTXOType } from "../tests/utils";
import jsonInput from "./data/send_and_receive_test_vectors.json";
import tweakVectors from "./data/tweak_test_vectors.json";

const ECPair = ECPairFactory(ecc);

function exactMatch(a: string[], b: string[]): boolean {
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.length === sortedB.length && sortedA.every((value, index) => value === sortedB[index]);
}

function matchSubset(generated: string[], expected: string[][]): boolean {
  return expected.some((subArray) => exactMatch(generated, subArray));
}

type Recipient = string | {
  address: string;
  scan_pub_key?: string;
  spend_pub_key?: string;
  count?: number;
};

type Given = {
  vin: Vin[];
  recipients: Recipient[];
};

type Expected = {
  outputs: string[][];
  shared_secrets?: Array<string | null>;
};

type Sending = {
  given: Given;
  expected: Expected;
};

type TestCase = {
  comment: string;
  sending: Sending[];
};

type TweakVectorInput = {
  txid: string;
  vout: number;
  scriptSig: string;
  witness: string[];
  prevoutScript: string;
};

type TweakVector = {
  comment: string;
  inputs: TweakVectorInput[];
  expected: {
    input_pub_keys: string[];
    input_pub_key_sum: string | null;
    tweak: string | null;
  };
};

const tests = jsonInput as unknown as Array<TestCase>;

function expandRecipients(recipients: Recipient[]): string[] {
  return recipients.flatMap((recipient) => {
    if (typeof recipient === "string") {
      return [recipient];
    }
    const count = recipient.count ?? 1;
    return Array.from({ length: count }, () => recipient.address);
  });
}

function buildTxFromTweakVectorInputs(inputs: TweakVectorInput[]): Transaction {
  const tx = new Transaction();
  for (const input of inputs) {
    tx.addInput(Buffer.from(input.txid, "hex").reverse(), input.vout, 0xfffffffd, Buffer.from(input.scriptSig, "hex"));
  }
  inputs.forEach((input, index) => {
    tx.setWitness(
      index,
      input.witness.map((witnessItem) => Buffer.from(witnessItem, "hex"))
    );
  });
  return tx;
}

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
    const recipients = expandRecipients(sending.given.recipients).map((address) => ({
      address,
      value: 1,
    }));

    it(`Sending: ${testCase.comment}`, () => {
      const sp = new SilentPayment();
      if (noEligibleUtxos) {
        expect(() => {
          sp.createTransaction(utxos, recipients);
        }).toThrow("No eligible UTXOs with private keys found");
      } else if (testCase.comment.includes("sum up to zero") || testCase.comment.includes("point at infinity")) {
        expect(() => {
          sp.createTransaction(utxos, recipients);
        }).toThrow("Sum of private keys is zero");
      } else if (testCase.comment.includes("K_max")) {
        expect(() => {
          sp.createTransaction(utxos, recipients);
        }).toThrow(`Silent payment elements for a single recipient group exceed the limit of ${K_MAX}`);
      } else {
        const generated = sp.createTransaction(utxos, recipients);
        const generated_pubkeys: string[] = generated.map((obj) => SilentPayment.addressToPubkey(String(obj.address))).filter(Boolean) as string[];
        assert(matchSubset(generated_pubkeys, sending.expected.outputs));
      }
    });
  });
});

/* Tweak / eligible-pubkey tests (Transaction + prevoutScripts API) */
(tweakVectors as TweakVector[]).forEach((testCase) => {
  it(`Tweak: ${testCase.comment}`, () => {
    const tx = buildTxFromTweakVectorInputs(testCase.inputs);
    const prevoutScripts = testCase.inputs.map((input) => hexToUint8Array(input.prevoutScript));

    const pubkeys = SilentPayment.getEligiblePubkeysFromTransactionInputs(tx, prevoutScripts);
    assert.deepStrictEqual(
      pubkeys.map((pubkey) => uint8ArrayToHex(pubkey)),
      testCase.expected.input_pub_keys
    );

    const sum = SilentPayment.sumPubKeys(pubkeys);
    if (testCase.expected.input_pub_key_sum === null) {
      assert.strictEqual(sum, null);
    } else {
      assert.strictEqual(uint8ArrayToHex(sum!), testCase.expected.input_pub_key_sum);
    }

    const tweak = SilentPayment.computeTweakForTx(tx, prevoutScripts);
    if (testCase.expected.tweak === null) {
      assert.strictEqual(tweak, null);
    } else {
      assert.strictEqual(uint8ArrayToHex(tweak!), testCase.expected.tweak);
    }
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
    uint8ArrayToHex(
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
      )
    ),
    "94d5923201f2f239e4d2d5a44239e0377325a343e4c068cfd078217adc663d7c"
  );
  assert.deepStrictEqual(
    uint8ArrayToHex(
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
      )
    ),
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

it("computeTweakForTx returns null without prevout scripts", () => {
  const tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c5000000000001000000013226000000000000225120e92e6cb44492f87779999fbbc295540eef8a23f42efdebacac001ffa18074c100140692f4e81047496cd755c4a24b54ae36e74f7e303a265b1a9a643774d5699a6723cc66e9cdd395d2e487f7881a74bbb5740241498e70ede269583f862a3d47b4600000000"
  );

  assert.strictEqual(SilentPayment.computeTweakForTx(tx, [new Uint8Array()]), null);
});

it("can create payment code out of BIP-39 seed", async () => {
  const code = SilentPayment.seedToCode("vault hole thought beyond young winter common federal measure hobby gold better salmon fetch exhibit follow strong genius large group galaxy doll assist tip");
  assert.strictEqual(code.address, "sp1qq2c7rt90jxqf35klz39hwkydm0ecnqtv9yrv620x7ehcd4tkra6lxq4f5j6l7ps78sru8fyhnjaqqwv4xanqr0zwg5tqe39d7y38l57f7cptdf26");

  assert.strictEqual(uint8ArrayToHex(code.bscan), "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d");
  assert.strictEqual(uint8ArrayToHex(code.Bspend), "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6");
});

it("can detect incoming payment in transaction using seed", async () => {
  // txid 511e007f9c96b6d713a72b730506198f61dd96046edee72f0dc636bfe1f3a9cf
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c5000000000001000000013226000000000000225120e92e6cb44492f87779999fbbc295540eef8a23f42efdebacac001ffa18074c100140692f4e81047496cd755c4a24b54ae36e74f7e303a265b1a9a643774d5699a6723cc66e9cdd395d2e487f7881a74bbb5740241498e70ede269583f862a3d47b4600000000"
  );

  const utxos = SilentPayment.detectOurUtxos(
    tx,
    "vault hole thought beyond young winter common federal measure hobby gold better salmon fetch exhibit follow strong genius large group galaxy doll assist tip",
    "032698de13d4b56f9e5f884daa14eaa1978d599fc4cdcb092c36f15e7498172d64"
  );
  assert.deepStrictEqual(utxos, [
    {
      txid: "511e007f9c96b6d713a72b730506198f61dd96046edee72f0dc636bfe1f3a9cf",
      vout: 0,
      wif: "L4PKRVk1Peaar5WuH5LiKfkTygWtFfGrFeH2g2t3YVVqiwpJjMoF", // thats bc1payhxedzyjtu8w7ven7au9925pmhc5gl59m77ht9vqq0l5xq8fsgqtwg8vf
      utxoType: "p2tr",
    },
  ]);
});

it("can detect incoming payment in transaction using tweak", async () => {
  // txid 511e007f9c96b6d713a72b730506198f61dd96046edee72f0dc636bfe1f3a9cf
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c5000000000001000000013226000000000000225120e92e6cb44492f87779999fbbc295540eef8a23f42efdebacac001ffa18074c100140692f4e81047496cd755c4a24b54ae36e74f7e303a265b1a9a643774d5699a6723cc66e9cdd395d2e487f7881a74bbb5740241498e70ede269583f862a3d47b4600000000"
  );

  const tweak = "032698de13d4b56f9e5f884daa14eaa1978d599fc4cdcb092c36f15e7498172d64";
  const bscan = "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d";
  const Bspend = "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6";

  const utxos = SilentPayment.detectOurUtxosUsingTweakbscanBspend(tx, tweak, bscan, Bspend);
  assert.deepStrictEqual(utxos, [
    {
      txid: "511e007f9c96b6d713a72b730506198f61dd96046edee72f0dc636bfe1f3a9cf",
      vout: 0,
      utxoType: "p2tr",
    },
  ]);
});

it("can detect incoming payment in transaction using seed 2", async () => {
  // txid c0deeef514bc1bcb959e51a414db1dc107ef299d9b140d1a6d7f4efe5f3f50f9
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c501000000000000008002102700000000000022512040fb1745d1c5f6d3f2b8825b83f6d90e74d6f278b0fe6d17e8173751e5bcaa4ab6ec0e00000000001600143adbcced77635b09bfe108295a8e39a73d1494b402483045022100d3f7a5edf1e592aae46499073eee7f93f63b1bda22bb83557918b42148128558022036a1dde48756f6d09dbf2ae884424d20985c6d8b05b5555eafd91d4de0b2238d0121033d484bbc02f16f0c5ada1fa14d8812e09e73cc8cf01ed9be3e78bda2322b778900000000"
  );

  const utxos = SilentPayment.detectOurUtxos(
    tx,
    "vault hole thought beyond young winter common federal measure hobby gold better salmon fetch exhibit follow strong genius large group galaxy doll assist tip",
    "03363f3e1db6a545fc3a98ce6c55d7bdc288009109442d539c09ebc7a7cb515aa1"
  );
  assert.deepStrictEqual(utxos, [
    {
      txid: "c0deeef514bc1bcb959e51a414db1dc107ef299d9b140d1a6d7f4efe5f3f50f9",
      utxoType: "p2tr",
      vout: 0,
      wif: "L1qJxwybxM8ntGs5XAt4yXp37o7PWYfvGwgxnJkR329YMaRCjxv1",
    },
  ]);
});

it("can detect incoming payment in transaction using tweak 2", async () => {
  // txid c0deeef514bc1bcb959e51a414db1dc107ef299d9b140d1a6d7f4efe5f3f50f9
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c501000000000000008002102700000000000022512040fb1745d1c5f6d3f2b8825b83f6d90e74d6f278b0fe6d17e8173751e5bcaa4ab6ec0e00000000001600143adbcced77635b09bfe108295a8e39a73d1494b402483045022100d3f7a5edf1e592aae46499073eee7f93f63b1bda22bb83557918b42148128558022036a1dde48756f6d09dbf2ae884424d20985c6d8b05b5555eafd91d4de0b2238d0121033d484bbc02f16f0c5ada1fa14d8812e09e73cc8cf01ed9be3e78bda2322b778900000000"
  );

  const tweak = "03363f3e1db6a545fc3a98ce6c55d7bdc288009109442d539c09ebc7a7cb515aa1";
  const bscan = "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d";
  const Bspend = "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6";

  const utxos = SilentPayment.detectOurUtxosUsingTweakbscanBspend(tx, tweak, bscan, Bspend);
  assert.deepStrictEqual(utxos, [
    {
      txid: "c0deeef514bc1bcb959e51a414db1dc107ef299d9b140d1a6d7f4efe5f3f50f9",
      utxoType: "p2tr",
      vout: 0,
    },
  ]);
});

it("can detect incoming payment in tx output (having output script only) using tweak", async () => {
  // txid 511e007f9c96b6d713a72b730506198f61dd96046edee72f0dc636bfe1f3a9cf
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c5000000000001000000013226000000000000225120e92e6cb44492f87779999fbbc295540eef8a23f42efdebacac001ffa18074c100140692f4e81047496cd755c4a24b54ae36e74f7e303a265b1a9a643774d5699a6723cc66e9cdd395d2e487f7881a74bbb5740241498e70ede269583f862a3d47b4600000000"
  );

  const outputScriptHex = uint8ArrayToHex(tx.outs[0].script);

  const tweak = "032698de13d4b56f9e5f884daa14eaa1978d599fc4cdcb092c36f15e7498172d64";
  const bscan = "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d";
  const Bspend = "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6";

  const isOurs = SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHex, tweak, bscan, Bspend);
  assert.strictEqual(isOurs, true);
});

it("can detect incoming payment in tx output (having output script only)  using tweak 2", async () => {
  // txid c0deeef514bc1bcb959e51a414db1dc107ef299d9b140d1a6d7f4efe5f3f50f9
  let tx = Transaction.fromHex(
    "02000000000101e79e2690d05d3589257a5d1094de7f46bb1cfae3fc3fb3b644b790d4337931c501000000000000008002102700000000000022512040fb1745d1c5f6d3f2b8825b83f6d90e74d6f278b0fe6d17e8173751e5bcaa4ab6ec0e00000000001600143adbcced77635b09bfe108295a8e39a73d1494b402483045022100d3f7a5edf1e592aae46499073eee7f93f63b1bda22bb83557918b42148128558022036a1dde48756f6d09dbf2ae884424d20985c6d8b05b5555eafd91d4de0b2238d0121033d484bbc02f16f0c5ada1fa14d8812e09e73cc8cf01ed9be3e78bda2322b778900000000"
  );

  const outputScriptHex = uint8ArrayToHex(tx.outs[0].script);
  const outputScriptHexWrong = uint8ArrayToHex(tx.outs[1].script); // not SP output, most likely change

  const tweak = "03363f3e1db6a545fc3a98ce6c55d7bdc288009109442d539c09ebc7a7cb515aa1";
  const bscan = "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d";
  const Bspend = "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6";

  const isOurs = SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHex, tweak, bscan, Bspend);
  assert.strictEqual(isOurs, true);

  const isOurs2 = SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHexWrong, tweak, bscan, Bspend);
  assert.strictEqual(isOurs2, false);
});

it("can detect incoming payment in tx output (having output script only)  using tweak 3, plus time measure", async () => {
  // txid ba7597f306e32836ba0dae64f760b2cb3ec6e5b5681ca93af878e49342016c10 height 933626
  const outputScriptHex = "51203fd5ab8ef219b411bd410e457766ce11057a502e07537e60b44fd7d90836e0d8";
  const tweak = "02670bbd884161533aefd5248fbe8143e5084dba0a82229094a90377a75fd5cd15";

  const bscan = "8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d";
  const Bspend = "02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6";

  const start = Date.now();
  for (let c = 0; c < 1000; c++) {
    const isOurs = SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHex, tweak, bscan, Bspend);
    assert.strictEqual(isOurs, true);
  }
  const end = Date.now();

  console.log("1000 tweak mults took", (end - start) / 1000, "sec");
});

it("can detect incoming payment in tx output (having output script only)  using tweak 3 v2, plus time measure", async () => {
  // txid ba7597f306e32836ba0dae64f760b2cb3ec6e5b5681ca93af878e49342016c10 height 933626
  const outputScript = hexToUint8Array("51203fd5ab8ef219b411bd410e457766ce11057a502e07537e60b44fd7d90836e0d8");
  const tweak = hexToUint8Array("02670bbd884161533aefd5248fbe8143e5084dba0a82229094a90377a75fd5cd15");

  const bscan = hexToUint8Array("8ec7ee5936f993b57dcc4e182eea413136e2a897b76328ae3ca19eca7804b45d");
  const Bspend = hexToUint8Array("02a9a4b5ff061e3c07c3a4979cba003995376601bc4e45160cc4adf1227fd3c9f6");

  const start = Date.now();
  let isOurs;
  for (let c = 0; c < 1000; c++) {
    isOurs = SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScriptUint8array(outputScript, tweak, bscan, Bspend);
  }
  assert.strictEqual(isOurs, true);
  const end = Date.now();

  console.log("1000 tweak mults took", (end - start) / 1000, "sec");
});

// Reporter scalars from BlueWallet/SilentPayments#30 (A + (-A) = 0 mod n).
const ISSUE30_A = hexToUint8Array("a6df6a0bb448992a301df4258e06a89fe7cf7146f59ac3bd5ff26083acb22ceb");
const ISSUE30_MINUS_A = hexToUint8Array("592095f44bb766d5cfe20bda71f9575ed2df6b9fb9addc7e5fdffe0923841456");
const ISSUE30_SP = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

function issue30P2wpkh(priv: Uint8Array, vout: number) {
  return {
    txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
    vout,
    wif: ECPair.fromPrivateKey(priv).toWIF(),
    utxoType: "p2wpkh" as UTXOType,
  };
}

it("sumPubKeys is order-independent when an intermediate sum is the point at infinity", () => {
  const Apub = ecc.pointFromScalar(ISSUE30_A, true);
  const minusApub = ecc.pointFromScalar(ISSUE30_MINUS_A, true);
  assert.ok(Apub);
  assert.ok(minusApub);

  const cancelFirst = SilentPayment.sumPubKeys([Apub, minusApub, Apub]);
  const cancelLast = SilentPayment.sumPubKeys([Apub, Apub, minusApub]);

  expect(cancelFirst).not.toBeNull();
  expect(cancelLast).not.toBeNull();
  assert.deepStrictEqual(cancelFirst, cancelLast);
  assert.deepStrictEqual(cancelFirst, Apub);
});

it("sumPubKeys returns null when the final sum is the point at infinity", () => {
  const Apub = ecc.pointFromScalar(ISSUE30_A, true);
  const minusApub = ecc.pointFromScalar(ISSUE30_MINUS_A, true);
  assert.ok(Apub);
  assert.ok(minusApub);

  assert.strictEqual(SilentPayment.sumPubKeys([Apub, minusApub]), null);
  assert.strictEqual(SilentPayment.sumPubKeys([Apub, minusApub, Apub, minusApub]), null);
});

it("createTransaction is order-independent when an intermediate privkey sum is zero", () => {
  const sp = new SilentPayment();
  const targets = [{ address: ISSUE30_SP, value: 1000 }];
  // Hand-checked: same dummy outpoints + scalar sum A → this taproot output.
  const expected = [{ address: "bc1p866w5jg45lp0phjw0qym0mmtcfvsstj7g03sqch4elu2j476vwfq63q9y0", value: 1000 }];

  assert.deepStrictEqual(sp.createTransaction([issue30P2wpkh(ISSUE30_A, 0), issue30P2wpkh(ISSUE30_MINUS_A, 1), issue30P2wpkh(ISSUE30_A, 2)], targets), expected);
  assert.deepStrictEqual(sp.createTransaction([issue30P2wpkh(ISSUE30_A, 0), issue30P2wpkh(ISSUE30_A, 1), issue30P2wpkh(ISSUE30_MINUS_A, 2)], targets), expected);
});

it("createTransaction throws when private keys sum to zero", () => {
  const sp = new SilentPayment();
  const targets = [{ address: ISSUE30_SP, value: 1000 }];
  const b = hexToUint8Array("0000000000000000000000000000000000000000000000000000000000000002");
  const minusAB = ecc.privateNegate(ecc.privateAdd(ISSUE30_A, b) as Uint8Array);

  expect(() => sp.createTransaction([issue30P2wpkh(ISSUE30_A, 0), issue30P2wpkh(ISSUE30_MINUS_A, 1)], targets)).toThrow("Sum of private keys is zero");
  expect(() =>
    sp.createTransaction([issue30P2wpkh(ISSUE30_A, 0), issue30P2wpkh(b, 1), issue30P2wpkh(minusAB, 2)], targets)
  ).toThrow("Sum of private keys is zero");
});

const K_MAX_SP_A = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const K_MAX_SP_B = "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn";

function repeatSpTargets(address: string, n: number) {
  return Array.from({ length: n }, () => ({ address, value: 1 }));
}

it("createTransaction throws when a recipient group exceeds K_max", () => {
  const sp = new SilentPayment();
  expect(() => sp.createTransaction([], repeatSpTargets(K_MAX_SP_A, K_MAX + 1))).toThrow(`Silent payment elements for a single recipient group exceed the limit of ${K_MAX}`);
});

it("createTransaction rejects an oversize later group before summing keys", () => {
  const sp = new SilentPayment();
  const targets = [{ address: K_MAX_SP_B, value: 1 }, ...repeatSpTargets(K_MAX_SP_A, K_MAX + 1)];
  expect(() => sp.createTransaction([], targets)).toThrow(`Silent payment elements for a single recipient group exceed the limit of ${K_MAX}`);
});

it("createTransaction allows a recipient group of exactly K_max", () => {
  const sp = new SilentPayment();
  expect(() => sp.createTransaction([], repeatSpTargets(K_MAX_SP_A, K_MAX))).toThrow("No UTXOs provided");
});

it("createTransaction produces outputs for a recipient group of exactly K_max", () => {
  const sp = new SilentPayment();
  const utxos = [
    {
      txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
      vout: 0,
      wif: ECPair.fromPrivateKey(hexToUint8Array("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192")).toWIF(),
      utxoType: "p2wpkh" as UTXOType,
    },
  ];
  const generated = sp.createTransaction(utxos, repeatSpTargets(K_MAX_SP_A, K_MAX));
  assert.strictEqual(generated.length, K_MAX);
  assert.ok(generated.every((target) => target.address?.startsWith("bc1p")));
});
