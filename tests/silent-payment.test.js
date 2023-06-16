/* global it */
import assert from "node:assert";
import { SilentPayment } from "../index";
import { ECPairFactory } from "ecpair";
import ecc from "../noble_ecc";
const bitcoin = require("bitcoinjs-lib");
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

it("smoke test", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(sp.createTransaction([], []), []);
});

it("1 input - 1 SP output works", () => {
  const sp = new SilentPayment();
  assert.deepStrictEqual(
    sp.createTransaction(
      [
        {
          txid: "a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb",
          vout: 0,
          WIF: "L4cJGJp4haLbS46ZKMKrjt7HqVuYTSHkChykdMrni955Fs3Sb8vq",
        },
      ],
      [
        {
          silentPaymentCode: "sp1qcttf6jjfamj040ucutkuzss56m0rdq9aeczlayuuxk5lt7yg0a0cdctc9aq2ekzr7pk39gf8d956u7aht9sskxmx27tm9mr5zjrxd2g6zkeep",
          value: 12_345,
        },
      ]
    ),
    [
      {
        address: "bc1pkrwcgdrye4e2uyfjchs54nucpwa7gq66hpzr68hcpxp739mxx29smlt4hf",
        value: 12_345,
      },
    ]
  );
});

it("2 inputs - 1 SP output works", () => {
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
          silentPaymentCode: "sp1qq97jk3z8rvuzhl4gvdap4rc8w7nqgta3eclpumsukk4zwl3z4xvkr47adrh60nwfqzrxzg4548xm4y2vtzppeavdjk6j2hnx7c484acs83jyj",
          // no value on purpose
        },
      ]
    ),
    [
      {
        address: bitcoin.payments.p2tr({ pubkey: Buffer.from("b4634de775abef75d72bac11b83184e64449c65f54b90fd5f95d8ca55987ef1e", "hex") }).address,
        // should be no value
      },
    ]
  );
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
        WIF: "L4cJGJp4haLbS46ZKMKrjt7HqVuYTSHkChykdMrni955Fs3Sb8vq",
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
      },
      {
        txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
        vout: 0,
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
