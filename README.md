# SilentPayments (BIP-352)

Send bitcoins to SilentPayment static payment codes, in pure typescript.

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
If youre using webpack you might need to add a loader in `webpack.config.js`:


```js
...
    {
        test: /node_modules\/silent-payments\/.*\.ts$/,
        use: [
          {
            loader: require.resolve('ts-loader'),
            options: {
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
    ),
```

Library will unwrap `sp1...` codes into correct receivers address. You _must_ provide correct UTXO types to the library, and you _must_ use the same UTXOs
in an actual transaction you create. Library will _not_ do coin selection for you.



## Development

- `npm i`
- `npm t`

## License

MIT

## References

- [https://github.com/bitcoin/bips/blob/1ae1b4bf80bc21911fbd90033edd8006d5e6b592/bip-0000.mediawiki](https://github.com/bitcoin/bips/pull/1458)
- https://github.com/josibake/silent-payments-workshop/blob/main/silent-payments-workshop.ipynb
- https://github.com/bitcoin/bitcoin/pull/27827
- https://medium.com/@ottosch/how-bip47-works-ee641cc14bf3
