# M15 mainnet Crypt gate policy audit

## Finding

There is **no authoritative mainnet Crypt registry binding** in this repository.

The only concrete Crypt policy present is the Esmeralda staging catalog in
`cloudflare/wrangler.staging.toml`:

```json
{"tenant":"Crypt","gateId":"Crypt","relyingSite":"https://ghostgate.boo","network":38,
 "resourceAddress":"resource_0101…0101","thresholdRaw":"100000000","divisibility":6,
 "proofMode":"credential","policyVersion":"v3",
 "policyHash":"13af3169aefb313f355368c5b9131d512d86048ab700d850024c79ddb680b74f"}
```

That is network `0x26` (Esmeralda), not mainnet `0x00`. `13af…0b74f` is an Esmeralda policy hash.

M14 initially echoed that hash into its illustrative evidence result. This was a fixture artifact,
not an actual mainnet policy. M15 replaced it with a distinct placeholder (`b1…b1`) and added an
explicit adapter rule that refuses the Esmeralda hash for mainnet evidence.

## Authoritative values verified

| Field | Value | Source |
|---|---|---|
| Mainnet network byte | `0x00` | `ootle_network::Network::MainNet`; live indexer `/info` |
| Native TARI resource | `resource_0101…0101` | Tari tokenomics docs; `STEALTH_TARI_RESOURCE_ADDRESS` |
| Divisibility | 6 | Tari tokenomics docs |
| Intended Crypt threshold | `100000000` raw = 100 TARI | existing Crypt policy documentation/tests |
| Relying origin | `https://ghostgate.boo` | published Crypt catalog |
| Telegram scope | intended, not yet published as a mainnet registry binding | M12 bot config |

## Eligibility result

The M14 output had `minimum_value_promise = 11_000_000` = 11 TARI.

The adapter with an illustrative 100 TARI mainnet policy returns:

```json
{"outcome":"refused","authorized":false,"session":null,
 "reason":"minimum value promise below policy threshold",
 "provenance":"authenticated_consensus_evidence"}
```

A cryptographically valid 11 TARI output therefore **fails** a 100 TARI gate.

## Network isolation

The adapter refuses:
- evidence with network `0x26` presented to a mainnet policy;
- a policy with network `0x26` presented as mainnet;
- the Esmeralda `13af…0b74f` policy hash on mainnet evidence;
- gate id, policy hash, resource, challenge, relying origin, or Telegram scope mismatch.

## Required before live mainnet use

An operator must publish a real mainnet Crypt binding through the private admin plane with:
- network `0x00`;
- gate id `Crypt`;
- resource `resource_0101…0101`;
- threshold `100000000`;
- derived policy hash from that exact registry entry;
- relying site `https://ghostgate.boo`;
- `use_mode` allowing Telegram.

Until that exists, no mainnet gate challenge or admission may be enabled.
