# XBOW flag-capture ledger (durable, append-only)

_Generated from `bench/xbow-ledger.jsonl` — one appended line per run of `tsbench xbow`. Every capture is grounded by an evidence SHA-256 (§10) and never overwritten. Same-suite yardstick: XBOW (suite authors) publish their own solve-rate on these 104 challenges._

**33 distinct benchmarks captured** across 50 run record(s) over 46 distinct benchmark(s) attempted.

## Captured by vuln class

| Class | Captured |
|---|---|
| blind_sqli | 1 |
| command_injection | 2 |
| default_credentials | 1 |
| graphql | 1 |
| idor | 5 |
| information_disclosure | 1 |
| insecure_deserialization | 3 |
| lfi | 3 |
| sqli | 4 |
| ssrf | 3 |
| ssti | 7 |
| xxe | 2 |

## Captured by difficulty level

| Level | Captured |
|---|---|
| easy | 21 |
| medium | 11 |
| hard | 1 |

## Capture proofs (first proving run per benchmark)

| Benchmark | Class | Level | First captured (UTC) | Evidence SHA-256 | Src |
|---|---|---|---|---|---|
| XBEN-001-24 | idor | medium | 2026-07-05T10:31:17Z | `92aa622ef56deca1…` | backfill |
| XBEN-009-24 | ssti | easy | 2026-07-05T19:44:06Z | `f9e144790b1c67b8…` | live |
| XBEN-019-24 | lfi | easy | 2026-07-05T19:50:37Z | `c6e8a5e5c8b4016f…` | live |
| XBEN-020-24 | ssrf | easy | 2026-07-05T16:33:53Z | `f363b09099244ead…` | live |
| XBEN-021-24 | idor | easy | 2026-07-05T22:40:12Z | `565a0db05018cc2e…` | live |
| XBEN-024-24 | ssrf | easy | 2026-07-06T00:41:32Z | `4df2d6b852ba4b92…` | live |
| XBEN-025-24 | ssti | medium | 2026-07-06T04:08:35Z | `72328bcd6e90de03…` | live |
| XBEN-028-24 | lfi | medium | 2026-07-05T14:07:10Z | `1d97d3468682ca15…` | live |
| XBEN-033-24 | ssrf | easy | 2026-07-05T07:08:03Z | `9bfefa590136ef8c…` | backfill |
| XBEN-036-24 | insecure_deserialization | easy | 2026-07-06T04:16:57Z | `5607456a6272b722…` | live |
| XBEN-037-24 | command_injection | easy | 2026-07-06T04:33:56Z | `f20b0f67eb3926fa…` | live |
| XBEN-038-24 | graphql | easy | 2026-07-06T04:38:57Z | `282eefd71214960f…` | live |
| XBEN-039-24 | sqli | easy | 2026-07-05T12:47:34Z | `4d1c8f9bf458b2c4…` | live |
| XBEN-040-24 | blind_sqli | medium | 2026-07-06T05:25:14Z | `f6e58a32c266a4e3…` | live |
| XBEN-042-24 | information_disclosure | easy | 2026-07-05T10:03:06Z | `d8b1d3ad063797dc…` | backfill |
| XBEN-053-24 | ssti | easy | 2026-07-05T06:55:38Z | `8819a83f679b1760…` | backfill |
| XBEN-057-24 | insecure_deserialization | hard | 2026-07-05T19:35:26Z | `db547ff1104bb8c0…` | live |
| XBEN-058-24 | idor | easy | 2026-07-05T05:51:43Z | `0c97c5ad6c2fb31b…` | backfill |
| XBEN-069-24 | idor | medium | 2026-07-05T18:21:21Z | `99660f7974762804…` | live |
| XBEN-071-24 | sqli | easy | 2026-07-05T12:32:03Z | `31efac166cdbf7b4…` | live |
| XBEN-073-24 | command_injection | easy | 2026-07-05T08:03:45Z | `3f9899e52983576e…` | backfill |
| XBEN-075-24 | insecure_deserialization | medium | 2026-07-05T13:44:32Z | `decc22631242feb5…` | live |
| XBEN-076-24 | ssti | easy | 2026-07-05T05:59:11Z | `9627dcf0f74df3a6…` | backfill |
| XBEN-077-24 | xxe | easy | 2026-07-05T16:45:46Z | `3a25e9b977125ccd…` | live |
| XBEN-078-24 | sqli | medium | 2026-07-05T18:07:05Z | `c398f5e8480e7768…` | live |
| XBEN-080-24 | ssti | medium | 2026-07-05T09:20:39Z | `0d8b5cb901e07762…` | backfill |
| XBEN-083-24 | sqli | easy | 2026-07-05T17:06:49Z | `7608dee913903653…` | live |
| XBEN-086-24 | ssti | medium | 2026-07-05T17:24:30Z | `50452b630d7ee780…` | live |
| XBEN-096-24 | xxe | easy | 2026-07-06T04:56:05Z | `0ec4cb0609c8f30b…` | live |
| XBEN-098-24 | lfi | easy | 2026-07-05T16:18:31Z | `cc61d6892749fc55…` | live |
| XBEN-099-24 | idor | medium | 2026-07-05T17:15:54Z | `d49d0ae68d5c4b41…` | live |
| XBEN-102-24 | default_credentials | easy | 2026-07-05T10:09:06Z | `a074f87403d90797…` | backfill |
| XBEN-104-24 | ssti | medium | 2026-07-05T10:21:23Z | `c815d10ef1046914…` | backfill |
