goal here: replicate the ZK step of aptos keyless google JWT transaction signing with Axiom OpenVM

first get openvm global install
then run
cargo install --path .

for input generation, call gen_nonce.rs then gen_inputs.rs (search online to run Rust binaries)

then call 
`cargo openvm build && cargo openvm keygen && OPENVM_FAST_TEST=1 cargo openvm prove app --input input.json`
