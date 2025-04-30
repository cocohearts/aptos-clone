goal here: replicate the ZK step of aptos keyless google JWT transaction signing with Axiom OpenVM

first get openvm global install
then run
cargo install --path .

for input generation: un-comment the binaries in Cargo.toml, then run `cargo run --bin gen_nonce && cargo run --bin gen_inputs -- jwt.txt`, then comment the binaries out again

then call 
`cargo openvm build && cargo openvm keygen && OPENVM_FAST_TEST=1 cargo openvm prove app --input input.json`
