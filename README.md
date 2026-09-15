# SilentPayments (BIP-352)

Send & receive bitcoins via SilentPayment (aka static payment codes), in pure typescript.

## Installation

- `npm i "github:BlueWallet/SilentPayments" --save`

Library is implemented in pure typescript _without_ js-compiled version committed - you might need to configure javascript build on your side.
For example, to use it in `jest` tests:

`package.json`:

```json
  "jest": {
    "transform": {
      "^.+\\.(ts|tsx)$": "ts-jest"
    },
    "transformIgnorePatterns": [
      "node_modules/(?!((jest-)?react-native(-.*)?|@react-native(-community)?)|silent-payments/)"
    ],
```

If youre using webpack you might need to add a loader in `webpack.config.js`, something like this:

```js
...
    {
        test: /node_modules\/silent-payments\/.*\.ts$/,
        use: [
          {
            loader: require.resolve('ts-loader'),
            options: {
              allowTsInNodeModules: true,
              getCustomTransformers: () => ({
                before: [isDevelopment && ReactRefreshTypeScript()].filter(
                  Boolean
                ),
              }),
              transpileOnly: isDevelopment,
            },
          },
        ],
      },
...
```

## Usage

### Send

You must provide UTXOs and targets (which might or might not include SilentPayment codes):

```typescript
createTransaction(utxos: UTXO[], targets: Target[]): Target[]
```

Finally:

```typescript
const sp = new SilentPayment();

const targets = sp.createTransaction(
  [
    {
      txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
      vout: 0,
      wif: ECPair.fromPrivateKey(Buffer.from("1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192", "hex")).toWIF(),
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
);
```

Library will unwrap `sp1...` codes into correct receivers address. You _must_ provide correct UTXO types to the library, and you _must_ use the same UTXOs
in an actual transaction you create. Library will _not_ do coin selection for you.

### Receive

Scanning is a two-step job. First derive the per-transaction tweak from the spending transaction and the scripts it spent (`prevoutScripts[i]` is the script of `tx.ins[i]`). Returns `null` when the transaction should be skipped (no eligible inputs, or the pubkey sum is the identity).

```typescript
const tweak = SilentPayment.computeTweakForTx(tx, prevoutScripts);
if (!tweak) {
  // skip this transaction
}
const tweakHex = Buffer.from(tweak).toString("hex");
```

The tweak can also come from a tweak-indexing backend (same 33-byte compressed pubkey, hex-encoded). Then detect outputs that belong to you.

With a BIP-39 seed (optional BIP-352 account index and passphrase; both default to account `0` and `""`):

```typescript
const utxos = SilentPayment.detectOurUtxos(tx, mnemonic, tweakHex);
// or: SilentPayment.detectOurUtxos(tx, mnemonic, tweakHex, accountNum, passphrase)
```

Each result is a taproot UTXO with a WIF spend key (`b_spend + t_k`). Detection walks unlabeled `k = 0, 1, …` until a gap or `K_MAX`.

If you already have `bscan` and `Bspend` (scan private key and spend public key as hex):

```typescript
const utxos = SilentPayment.detectOurUtxosUsingTweakbscanBspend(tx, tweakHex, bscanHex, BspendHex);
```

To check a single output script in isolation (only `k = 0`; later `k` need the full transaction via `detectOurUtxos*`):

```typescript
SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScript(outputScriptHex, tweakHex, bscanHex, BspendHex);
SilentPayment.isOurUtxoUsingTweakbscanBspendAndOutputScriptUint8array(outputScript, tweak, bscan, Bspend);
```

Labeled addresses (`m ≠ unlabeled B_spend`) are not scanned. `seedToCode` produces the unlabeled `sp1…` payment code plus the scan/spend keys used above.

## Development

- `npm i`
- `npm t`

## License

MIT

## References

- https://github.com/josibake/silent-payments-workshop/blob/main/silent-payments-workshop.ipynb
- https://github.com/bitcoin/bitcoin/pull/27827
- https://medium.com/@ottosch/how-bip47-works-ee641cc14bf3
- https://medium.com/@ottosch/how-silent-payments-work-41bea907d6b0
- https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
- https://github.com/bitcoin/bips/blob/97012a82064c7247df502a170c03b053825cdd15/bip-0352/reference.py
