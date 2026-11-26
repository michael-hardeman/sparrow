# Response to PR #4 review (michael-hardeman, 2026-11-24)

Point-by-point decisions on the review feedback. Status: **done** = changed in this branch,
**disagree** = kept as is with reason, **open** = accepted but not done here.

The full proof suite still passes: `tests/prove.sh` over all 9 crates, plus `design/check.py` and
`examples/snippets/generate.sh --check`.

## Inline comments: `SPARK_Mode => Off` with `Pre`/`Post`

The author's rule is right and was applied: contracts must live on a **SPARK declaration**, with the `Off`
only on the body or a private part. Putting `SPARK_Mode => Off` on the declaration itself makes the
contracts invisible to the proof. Earlier note in `design/proof-lessons.md` that an "off declaration with
contracts" is callable from SPARK was wrong and has been corrected.

| File | Decision |
|---|---|
| `sparrow-http-static.ads` — `Serve_File` | **done.** Declaration is SPARK with `Pre`/`Post`; body remains Off (file I/O, address overlay, heap). |
| `sparrow-http-static.ads` — `Routes`, `Handle`, `Make`, `Folder` | **done.** `Routes` genuinely cannot be SPARK: E0003 on its controlled/access components, E0005 on heap state, plain `Pre` on a dispatching operation is illegal, and access components of a tagged extension are illegal. It stays Off; the `Pre`/`Post` that gnatprove would ignore were removed. `Max_Age_Of`, added only to support a `Post`, was removed too. |
| `sparrow-http-requests.ads` — `Json_Body` | **done.** Declaration is SPARK; body stays Off because a return with computed `Document` discriminants is illegal in SPARK (E0007) and a maximum-size document would allocate ~1M nodes. The `Post` was reduced to the one non-redundant property the author suggested. The capacity scan remains a proved SPARK helper. |
| `sparrow-http-compression.ads` — `Apply` | **done.** Declaration is SPARK with `Global`, `Pre`, `Post`; body stays Off (heap compressor pool, E0019). The original `Post` used `'Old` on a by-copy `in out` parameter and was genuinely rejected once the Off was removed, as the author suspected; it is now just validity. `Apply` calls the proved `Compressible_Response` and then `Accepts_Gzip`, in that order — see the Vary regression below. |

## Review points 1–10

1. **`--timeout=10` / `-j6` vs `--steps` / `-j0`.** **done.** Agreed with the author: proof results must not depend on runner speed. `tests/prove.sh` now uses `-j0 --steps=200000 --timeout=300`. 200k is about 4.5x the largest step count recorded in this tree's proof sessions (~43k); the timeout is only a generous safety cap, not the limit that decides a proof. The core crate README documents the same command.
2. **Decision record for the prover change.** **open.** Agreed: per AGENTS.md this needs a decision record (new, or superseding 0004/0014). I did not add one because decision records are the author's call; this is the main thing I would add before merge.
3. **`Global => null` on `Parse_Jwks`.** **disagree, with evidence.** Removing the aspect fails at E0005: gnatprove generates an output global "memory accessed through objects of access type" and rejects a function with that effect. The `Document` is allocated and freed locally; no program global is touched. The aspect was kept with a one-line reason at the declaration. If the author wants the real heap effect stated, that needs a named abstract state, which would leak into every caller's `Global` contract.
4. **`design/proof-lessons.md` contains history/stale facts.** **done.** Rewritten as durable techniques only: boundary rules, proof patterns, process. Version numbers, timings, "was Off"/"Fixed" history, prover-specific claims and the to-do list were removed. Git holds the history.
5. **`Postgres_Wire.Float_Value` can drop its `Off`.** **done.** Off removed; the body now proves, and only `Float_4_Value` / `Float_8_Value` stay Off for `Unchecked_Conversion`.
6. **`Parse_Into` adds nothing.** **done.** Removed; `Json_Body` calls `Json.Parse` directly. The proved `Node_Capacity_For` remains, since it contains the actual byte scan.
7. **`Needs_Rehash` repeats `Parse`'s length check.** **done.** `Parse` now has `Post => (if Valid then Stored'Length <= Max_Stored_Length)`; the duplicate check is gone.
8. **Contracts in `Queries` / `Migrations` (fully Off packages) are not checked.** **agree in substance, kept.** They are documentation for now; gnatprove ignores them. They were left in place because they state the intended behavior and are checked at runtime where assertions are enabled. The commit message overstates them; a corrected message cannot be added without rewriting pushed history, so this note is the correction.
9. **`Postgres_Wire` public API grew for contracts.** **open.** `Signed_Word`, `Finite_4/8`, `Float_4/8_Value` and `Array_Header` are now visible. A private child package is the clean fix; the full-equality `Post`s on `Integer_Value` / `Element_Count` could also be dropped if no SPARK caller needs them. Not done here to keep the change focused.
10. **Hot-path benchmarks for `Find` / `Read_Integer`.** **open.** Agreed per AGENTS.md. I could not run `tests/bench` here: the environment lacks `libpq`, `libssl`, `libcrypto` and `libsqlite3`, so test/example/fuzz binaries do not link. Needs a run on a machine with those libraries.

## Nits

- Computed `Powers` as `[for I in Scrypt_Cost => 2 ** I]`: **tried and reverted.** With 10 s provers, the overflow check on `Block_Size * Power` no longer proves (the symbolic `2 ** Last` gives no concrete bound, even with an assertion). Explicit constants stay.
- `Separator_Of` index subtype `1 .. 3`: **done**, removing `when others` and an assertion.
- `Coordinate_Bytes` also naming the Ed25519 seed, `Signature_Bytes` scope, duplicate RSA comment: **open**, cosmetic.
- `Eligible` duplicating `Apply`'s checks: **done**, but see the regression below: `Apply` calls
  `Compressible_Response` and `Accepts_Gzip` separately to preserve the order of the `Vary` side effect.
- Review type "Request changes": agreed; points 1, 2 and 10 were real blockers to merge.

## Follow-up: Vary regression (maintainer comment, 2026-11-25)

The maintainer found a real regression caused by my change: folding the client check into `Eligible` made
`Apply` test `Accept-Encoding` before adding `Vary: Accept-Encoding`. A client that does not accept gzip then
got a plain response without `Vary`, so a shared cache could serve it to gzip clients.

**Fixed as suggested:** `Compressible_Response` holds the response-only checks; `Eligible` is that plus
`Accepts_Gzip`; `Apply` checks `Compressible_Response`, adds `Vary`, then checks `Accepts_Gzip`. This
restores the original order. `tests/src/http_tests.adb:1262` is the regression test the maintainer cited.
HTTP proof passes with the new configuration; the test suite cannot be linked in this environment because
the system's `libpq`, `libssl`, `libcrypto` and `libsqlite3` development libraries are absent, so CI must
confirm the two previously failing HTTP tests and the ThreadSanitizer job.
