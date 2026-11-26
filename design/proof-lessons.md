# Proof notes

Durable techniques for working on the SPARK proofs. Not a decision record; architecture rules live in
`rules.toml` and `decisions/`.

## Boundary rules

- A SPARK declaration may have an `SPARK_Mode => Off` **body**; its callers use the `Pre`/`Post`/`Global` on
  the declaration. Do not put `SPARK_Mode => Off` on a declaration that carries contracts: the contracts are
  then ignored. Either move the Off to the body/private part, or drop the contracts.
- A package spec can be SPARK with an Off private part and body. This keeps the visible declarations under
  proof; C handles, Ada containers and access types go behind the private part.
- Contracts on Off bodies are assumptions, not checks. Keep them true by hand, and prefer a SPARK helper
  over restating a decision in a contract. `--proof-warnings=on` can expose an inconsistent contract through
  unreachable branches in its SPARK callers, but it is not complete.
- GNATprove generates coarse globals for non-SPARK bodies; for access types these are `__HEAP` and can be
  wrong or rejected (E0005 on a function). State the real global effects explicitly instead of relying on
  generation.
- GNATprove assumes `'Valid` is true. Express validity in a contract as an equivalent checked condition
  (for floats, the IEEE exponent bits) and keep the body's `'Valid` test in step with it.
- `'Old` on a by-copy `in out` parameter is not allowed in a SPARK postcondition. Do not hide an illegal
  postcondition behind `SPARK_Mode => Off`; simplify it or pass the parameter by reference.

## Proving timingouts

- A check that times out just after an `exit when` usually lacks bounds on the loop variable at that point.
  Put checked assertions immediately after the exit: they follow from the negated exit condition and give
  provers explicit bounds for the rest of the iteration.
- `Annotate => (GNATprove, No_Bitwise_Operations)` on a modular type makes provers model it as an integer
  instead of a bit vector. Put it on a derived type if the original needs shifts or `and`/`or`.
- Nonlinear products with a `mod` expression or an array select are hard: bind the factors to local
  constants with explicit bound assertions, then multiply the constants.
- A `pragma Assert` on a symbolic bound such as `2 ** Last` may prove but leave the concrete bound unknown;
  use explicit constants when the bound must be computed in arithmetic.

## Process

- When extracting a repeated condition into a helper, preserve its position relative to side effects. In
  `Apply`, `Vary: Accept-Encoding` must be set before the client's `Accept-Encoding` is checked, otherwise
  plain responses are cacheable as if they were gzip-encoded. Keep the response-only check and the client
  check separate.
- Prefer `--steps` over `--timeout` for reproducible results: wall-clock limits change with machine load,
  step limits do not. Keep a generous timeout only as a safety cap, and set the step limit well above the
  largest step count in the proof session files.
- Prove all crates after changing a spec or prover settings: a prover that succeeds on small crates may be
  needed by one check in a large one. `tests/prove.sh` stops at the first failing crate.
- Use `gnatprove --clean` before a full run; session files can hide a check that only another prover solved.
- Use `--limit-line=<file>:<line>` for a single failing check, and `--report=provers` to see which prover
  actually discharges it.
