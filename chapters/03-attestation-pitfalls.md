# Attestation Pitfalls

Attestation is what makes a TEE useful to remote parties. It is also where many deployments go wrong, without any hardware bug at all.

## What an attestation contains

- A **measurement** (hash) of the initial code and configuration (MRENCLAVE/MRSIGNER for SGX; MRTD/RTMRs for TDX; launch measurement for SEV-SNP).
- **Report data**: a small field the enclave fills, typically a hash of a public key, binding a secure channel to the attestation.
- **Platform TCB info**: firmware and microcode versions.
- A **signature chain** back to the vendor's root.

The verifier's job is to turn these fields into a yes/no decision. Every field the verifier does not check is a field the attacker controls. In IETF RATS terms (RFC 9334), the TEE is the *attester*, your service is the *relying party*, and the policy that maps evidence to a decision lives in a *verifier*, which may be your own code or a hosted attestation service you then have to trust.

## Common mistakes

| Mistake | Consequence |
|---|---|
| Verifying the signature but not the measurement | any enclave on genuine hardware is accepted |
| Accepting `MRSIGNER` instead of a specific `MRENCLAVE` | any enclave signed by the same key, including old vulnerable versions |
| Not binding a channel key in report data | attacker relays a genuine attestation and talks to you from outside |
| Ignoring TCB status / debug flags | accepts debug-mode enclaves (memory readable) or vulnerable platforms |
| Measuring only the bootloader in a CVM | the OS or app loaded later is not covered |
| No reproducible builds | nobody can check what the measurement corresponds to |
| Stale collateral / revocation not checked | accepts revoked platforms |

`MRSIGNER` policies are not always wrong. They let a vendor ship updates without every relying party changing its allowlist. If you use them, also enforce a minimum ISV security version number (ISVSVN) so that old, vulnerable builds signed by the same key are rejected.

## Confidential VM specifics

For TDX and SEV-SNP, the initial measurement covers firmware and possibly the kernel. Everything loaded later must be measured into runtime registers (RTMRs, vTPM PCRs), and the verifier must check those too. A CVM that measures firmware but downloads its application at boot proves almost nothing.

Cloud CVMs add a twist: the firmware is often supplied by the cloud provider, so the launch measurement corresponds to the *provider's* firmware build. Unless the provider publishes reproducible firmware, you are trusting them for that part of the chain. Several providers expose a vTPM inside the guest, with its own attestation path; then you must verify both the hardware report and the vTPM's binding to it.

```mermaid
sequenceDiagram
    participant RP as Relying party
    participant T as TEE (attester)
    participant PKI as Vendor collateral (certs, TCB info, CRLs)
    RP->>T: nonce
    T->>T: create keypair; report_data = H(nonce || pubkey)
    T-->>RP: evidence (report/quote) + pubkey
    RP->>PKI: fetch collateral
    RP->>RP: chain OK? not revoked? TCB >= min? debug off?
    RP->>RP: measurement in allowlist? report_data matches?
    RP-->>T: secret encrypted to pubkey (only if all pass)
```

## Verification checklist

- [ ] Signature chain to vendor root; collateral fresh; revocation checked.
- [ ] Exact measurement(s) match a reproducible build.
- [ ] Debug mode disabled.
- [ ] TCB level meets a minimum policy.
- [ ] Report data binds a fresh nonce and the channel's public key.
- [ ] Runtime measurements cover the application.

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally. Outputs described as "expected" are what the tools should show, not observed results. Requires a report from your own SEV-SNP VM; confirm offsets against the ABI specification.

Write the *policy* half of an SEV-SNP verifier and prove it rejects bad reports. Signature and certificate-chain checks are delegated to a maintained tool (VirTEE `snpguest verify attestation`); the policy is what teams usually get wrong.

**Step 1: parse the fields you need.** The SNP attestation report is a fixed binary layout defined in AMD's SEV-SNP ABI specification. For current report versions, the guest policy is a 64-bit field at offset `0x08`, report data is 64 bytes at `0x50`, and the launch measurement is 48 bytes at `0x90`. Confirm offsets against the specification version your platform reports before relying on them.

```python
import struct, hashlib, sys

DEBUG_BIT = 1 << 19          # policy bit: debugging allowed
ALLOWED = {bytes.fromhex(open("expected_measurement.hex").read().strip())}

def check(report: bytes, nonce: bytes, pubkey: bytes) -> list[str]:
    errs = []
    policy = struct.unpack_from("<Q", report, 0x08)[0]
    report_data = report[0x50:0x90]
    measurement = report[0x90:0xC0]
    if policy & DEBUG_BIT:
        errs.append("debug allowed")
    if measurement not in ALLOWED:
        errs.append("unknown measurement")
    if report_data != hashlib.sha512(nonce + pubkey).digest():
        errs.append("report_data does not bind nonce+key")
    return errs

r = open(sys.argv[1], "rb").read()
print(check(r, bytes.fromhex(sys.argv[2]), open(sys.argv[3], "rb").read()) or "ACCEPT")
```

**Step 2: negative tests.** Take a real report from your own CVM and produce mutated copies:

| Test | Mutation | Expected output |
|---|---|---|
| Wrong code | flip one byte at `0x90` | `unknown measurement` |
| Debug VM | launch a VM with debug policy, fetch a report | `debug allowed` |
| Replay | reuse yesterday's report with a new nonce | `report_data does not bind nonce+key` |
| Forged fields | any mutation | signature check in `snpguest` fails first |

The fourth row matters: mutated reports must also fail the signature check. If your pipeline runs the policy check *without* the signature check, a mutated report that happens to satisfy the policy is accepted. Run both, signature first, and fail closed.

**Step 3: wire it into key release.** Your service releases a secret only when both `snpguest verify` and `check()` succeed. Log every rejection reason; a sudden rise in `unknown measurement` often means an unannounced image change.

## Common pitfalls

- **Parsing before verifying.** Policy logic on unsigned bytes invites confusion; verify the signature first.
- **Allowlists that only grow.** Old measurements stay accepted forever unless you remove them when you ship fixes.
- **Trusting a hosted verifier blindly.** A cloud attestation service becomes part of your TCB; read what it actually checks.
- **Hashing report data inconsistently.** Byte order, encoding of the public key (DER vs raw) and padding all cause false rejects, and engineers then "temporarily" disable the check.
- **No plan for TCB updates.** When the vendor bumps the TCB, the minimum policy must move, or patched and unpatched platforms look the same.

## Exercises

1. Verify an SGX DCAP quote or SEV-SNP report with an open-source verifier and print each field.
2. Write a verifier that forgets the debug-flag check, then attest a debug enclave to it.
3. Build an application image reproducibly and show two builds yield the same measurement.
4. Extend the worked example to check a minimum reported TCB version, and test it against an older firmware level if you can obtain one.

## Further reading

- Intel DCAP: <https://github.com/intel/SGXDataCenterAttestationPrimitives>
- AMD SEV-SNP ABI specification (attestation report format), via <https://www.amd.com/en/developer/sev.html>
- VirTEE `snpguest`: <https://github.com/virtee/snpguest>
- IETF RATS architecture, RFC 9334: <https://www.rfc-editor.org/rfc/rfc9334>
- Gramine (library OS for SGX): <https://gramine.readthedocs.io>
