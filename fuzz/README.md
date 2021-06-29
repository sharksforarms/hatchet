# Fuzzing

## Coverage

Example to retreive coverage

```
cargo +nightly fuzz run fuzz_tcp
cargo +nightly fuzz coverage fuzz_tcp
llvm-cov show -format=html -output-dir=cov/ -instr-profile=./coverage/fuzz_tcp/coverage.profdata target/x86_64-unknown-linux-gnu/release/fuzz_tcp
firefox cov/index.html
```
