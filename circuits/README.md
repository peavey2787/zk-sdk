# Circuits

Sources for the circuits whose compiled `.r1cs`/`.sym` (and a reference `.wtns` for `age_over`) live in `testdata/`.

| Circuit | Statement |
|---|---|
| `age_over.circom` | private `age` is greater than public `threshold`; output `over` |
| `millionaires.circom` | private `alice` wealth is greater than private `bob` wealth; output only the verdict |
| `arithmetic.circom` | `y = (x * secret + x)^2 + 3` with public `x` and private `secret` |
| `range7.circom` | 7-bit decomposition only; **does not** bind a witness to a commitment |

Comparison circuits (`lib/compare.circom`) are range-checked. The KoalaBear field is 31 bits, so `LessThan(n)` is only sound for `n <= 29`.

Recompile with the KoalaBear fork of Circom (`-p koalabear`):

```sh
circom circuits/age_over.circom -p koalabear --r1cs --sym -o testdata/age_over
```

No C++ witness generator is needed: `zk-witness` solves the witness from the `.r1cs`/`.sym` pair in Rust, natively and in WebAssembly, and always re-checks that every constraint holds.
