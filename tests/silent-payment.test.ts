import assert from "node:assert";
import { ECPairFactory } from "ecpair";

import { SilentPayment } from "../src";
import ecc from "../src/noble_ecc";
import jsonImput from "./data/sending_test_vectors.json";

const ECPair = ECPairFactory(ecc);

type TestCase = {
  comment: string;
  given: {
    outpoints: [string, number][],
    input_priv_keys: [string, boolean][],
    recipients: [string, number][]
  },
  expected: {
    outputs: [string, number][],
  }
}

const tests = jsonImput as unknown as Array<TestCase>;

it("smoke test", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(sp.createTransaction([], []), []);
});

/* Sending tests from the BIP352 test vectors */
tests.forEach((testCase, index) => {
  // Prepare the 'inputs' array
  const inputs = testCase.given.outpoints.map((outpoint, idx) => ({
    txid: outpoint[0],
    vout: outpoint[1],
    WIF: ECPair.fromPrivateKey(Buffer.from(testCase.given.input_priv_keys[idx][0], "hex")).toWIF(),
    isTaproot: testCase.given.input_priv_keys[idx][1],
  }));

  // Prepare the 'recipients' array
  const recipients = testCase.given.recipients.map((recipient) => ({
    silentPaymentCode: recipient[0],
    value: recipient[1],
  }));

  it(`Test Case: ${testCase.comment} works`, () => {
    const sp = new SilentPayment();
    assert.deepStrictEqual(
      sp.createTransaction(inputs, recipients),
      testCase.expected.outputs.map((output) => {
        const address = output[0];
        const value = output[1];
        return {
          address: address,
          value: value,
        };
      })
    );
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
          WIF: ECPair.fromPrivateKey(Buffer.from("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192", "hex")).toWIF(),
        },
        {
          txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
          vout: 0,
          WIF: ECPair.fromPrivateKey(Buffer.from("7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056", "hex")).toWIF(),
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

it("SilentPayment._outpointHash() works", () => {
  assert.deepStrictEqual(
    SilentPayment._outpointsHash([
      {
        txid: "a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb",
        vout: 0,
        WIF: "",
      },
    ]).toString("hex"),
    "dc28dfeffd23899e1ec394a601ef543fa4f29c59e8548ceeca8f3b40fef5d041"
  );

  // multiple outpoints

  assert.deepStrictEqual(
    SilentPayment._outpointsHash([
      {
        txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
        vout: 0,
        WIF: "",
      },
      {
        txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
        vout: 0,
        WIF: "",
      },
    ]).toString("hex"),
    "210fef5d624db17c965c7597e2c6c9f60ef440c831d149c43567c50158557f12"
  );
});

it("SilentPayment._ser32() works", () => {
  assert.strictEqual(SilentPayment._ser32(0).toString("hex"), "00000000");
  assert.strictEqual(SilentPayment._ser32(1).toString("hex"), "00000001");
  assert.strictEqual(SilentPayment._ser32(444).toString("hex"), "000001bc");
});
