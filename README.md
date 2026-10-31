# QData

Post quantum attestations for private data stores on the Quantova network. QData lets the party that holds a data store prove how that store is governed without ever revealing the data. A store is registered, records and datasets are committed by digest, access is logged, retention is set and erasure is recorded. Each record is signed with ML-DSA-65 under FIPS 204 and may be anchored to a Quantova time proof. Only a salted commitment ever leaves the holder, never the data itself.

## Install

```
npm install @quantovainc/qdata
```

## Model

A QData record is a signed envelope. The statement names a store by a random identifier and carries only commitments and governance facts. The five record types form a chain.

- register opens a store and names its system and data classification
- commit seals the digest of a record or dataset held in that store
- access logs who read, exported, modified, shared or deleted data
- retain records the retention policy and the time retention expires
- erase records that data was erased and by what method

commit refers back to the register of its store. access, retain and erase refer to the record they follow. The chain lets any party replay the history of a store from its signed records.

## Use

```js
const Q = require('@quantovainc/qdata')

const key = Q.generateKey()

const store = Q.register({
  key,
  system: 'customer-records',
  classification: 'confidential',
  authorityLabel: 'Data Protection Office',
})

const sealed = Q.commit({
  key,
  store,
  recordId: 'export-batch-01',
  digestAlg: 'sha-256',
  digest: 'a'.repeat(64),
  scope: 'the nightly export of the customer table',
})

const result = await Q.verify(sealed, { network: 'testnet', prior: store })
console.log(result.status)
```

## Verify

verify checks the ML-DSA-65 signature, that the signer is the authority the record names, the optional prior link, and any Quantova anchor. It returns a status of valid, unproven, indeterminate or invalid together with the individual checks. An anchor is accepted only when it was recorded under the QData record kind on the network named in the options.

## Keys

A signing key is a 32 byte seed produced by generateKey. The seed stays with its holder and never appears in a record. A public key and a key identifier derived from it are what other parties use to verify.

## License

Apache-2.0 OR MIT. See LICENSE-APACHE and LICENSE-MIT.
