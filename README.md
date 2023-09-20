# Zero Knowledge Proofs for Supply Chain's Carbon Calculation

This is a simple setup to run the PCF Calculations

## Dependencies:

- ZoKrates (v0.8.7 confirmed)

## How to run:

- `./run.sh`

### Workflow:

Our script performs several steps for Zero-Knowledge Proof (ZKP) generation and verification using Zokrates.

1. **Audit:** Runs `attestation.py` with example inputs values from `input.json`, storing output in `witness-parameters.txt`.
2. **Compilation:** Compiles zkSnark code in `poc.zok` with Zokrates, noting the compiled size and timing the process.
3. **Zokrates Setup:** Sets up ZKP Circuit with the compiled code, generates a proving key and verification key, and logs their sizes and the timings.
4. **Witness Generation:** Creates a witness, timing the process.
5. **Proof Generation:** Generates a proof using the witness, proving key, compiled code, and times the process.
6. **Verification:** Verifies the proof with the verification key, timing the verification process.

Finally, the script logs the times and sizes of the compiled code, proving key, and verification key.
