# Side-Channel Attacks on TEEs

Side channels are the dominant attack class against TEEs. The host cannot read enclave memory directly, but it can observe *effects* of enclave execution.

## Channel types

| Channel | What leaks | Example research |
|---|---|---|
| Page faults / controlled channel | which pages are accessed | Xu et al., "Controlled-Channel Attacks", IEEE S&P 2015 |
| Cache timing | which cache lines are accessed | Prime+Probe on SGX (many papers) |
| Single-stepping | instruction-level timing and control flow | SGX-Step framework |
| Transient execution | speculative reads of secrets | Foreshadow (2018), ZombieLoad, RIDL |
| Voltage/frequency | fault injection via undervolting | Plundervolt (2019) |
| Architectural bugs | stale data in CPU buffers | ÆPIC Leak (2022) |
| Ciphertext side channels (SEV) | deterministic encryption reveals equal values | CipherLeaks (2021) |
| Interrupt/injection on CVMs | malicious interrupts into confidential VMs | Heckler, WeSee (2024) |

## The pattern behind most of them

Secret-dependent behaviour (branches, memory accesses, timing) + a host that can observe or manipulate that behaviour precisely = leakage. The host's ability to single-step enclaves turns small leaks into full key extraction.

Consider granularity. Page-fault attacks see 4 KiB pages. Cache attacks see 64-byte lines. Single-stepping sees individual instructions. Each step down in granularity defeats a class of "mostly constant-time" code that was safe at the coarser level. For example, a lookup table that fits in one page leaks nothing to a page-fault observer, but leaks its index to a cache observer.

The classes also split by what fixes them:

| Class | Fixed by software? | Fixed by microcode/firmware? | Residual risk |
|---|---|---|---|
| Controlled channel, cache timing | yes (constant-time code) | no | code you did not review |
| Transient execution, buffer leaks | partly | yes (TCB recovery) | unpatched platforms |
| Fault injection (voltage) | partly (redundant checks) | yes (interface locked) | physical attackers |
| CVM interface attacks (interrupts, ciphertext) | yes (guest kernel hardening) | partly | guest kernel versions |

## Defences

- **Constant-time code:** no secret-dependent branches or memory indices. Use audited constant-time crypto libraries.
- **Microcode updates and TCB recovery:** vendors fix hardware issues with microcode and increase the TCB version; attestations report it.
- **Attestation policy:** reject platforms with outdated TCB levels.
- **Oblivious algorithms** for data-dependent access (ORAM-style) when the access pattern itself is secret.
- **Defence in depth:** do not rely on a single TEE for very high-value secrets. Combine with threshold cryptography (see **MPC Wallet Security**).

## Worked example

> **Execution status:** Not executed in this book's CI; verify locally. Outputs described as "expected" are what the tools should show, not observed results. The timing harness in Step 2 is described, not provided in full.

You do not need an enclave to learn the core lesson. A malicious host's view is a timing or access trace; you can generate one locally and detect leakage statistically, the way the dudect tool does.

**Step 1: two comparison functions.**

```c
// leak.c
#include <stdint.h>
#include <stddef.h>
int cmp_leaky(const uint8_t *a, const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;  // early exit
  return 1;
}
int cmp_ct(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}
```

**Step 2: a measurement harness.** Feed two classes of input: class A shares a long prefix with the secret, class B shares none. Time each call with the cycle counter (`__rdtsc()` from `x86intrin.h`) for, say, 100,000 interleaved samples per class, and write `class,cycles` lines to a CSV.

**Step 3: test for a difference.** Welch's t-test on the two classes:

```python
import csv, statistics as st, math
a, b = [], []
for cls, cyc in csv.reader(open("times.csv")):
    (a if cls == "A" else b).append(int(cyc))
t = (st.mean(a) - st.mean(b)) / math.sqrt(st.variance(a)/len(a) + st.variance(b)/len(b))
print(f"t = {t:.1f}")
```

Expected result: `cmp_leaky` gives a large |t| (dudect treats values above about 4.5 as evidence of leakage), while `cmp_ct` stays small. Compile with `-O2` and inspect the assembly: compilers sometimes turn "constant-time" C into branches, so the statistical test, not your reading of the source, is the check.

**Step 4: relate it to an enclave.** Inside SGX, the host does not need noisy wall-clock timing. With a framework like SGX-Step it can interrupt after every instruction and count steps, so the early-exit loop reveals the matching prefix length exactly. Only run SGX-Step on your own SGX machine; it requires a kernel module and changes system behaviour.

## Common pitfalls

- **Trusting source-level constant-time code.** Compilers and optimisation levels change it. Check binaries or measure.
- **Testing on a quiet laptop only.** Noise hides leaks that a single-stepping host would see cleanly.
- **Treating microcode fixes as automatic.** They protect you only if the verifier rejects old TCB versions.
- **Forgetting memory access patterns.** Table lookups indexed by secrets leak through caches even with no branches.
- **Assuming CVMs are immune.** Interface-level attacks on confidential VMs target the guest kernel, which you control and must patch.

## Exercises

1. Read the SGX-Step paper and explain why single-stepping amplifies leakage.
2. Find a secret-dependent branch in a sample enclave program and rewrite it constant-time.
3. Check which TCB versions your cloud's confidential VMs report and whether they include fixes for recent advisories.
4. Run the worked example with `-O0` and `-O3`. Does either version of `cmp_ct` leak?

## Further reading

- Van Bulck et al., "SGX-Step: A Practical Attack Framework for Precise Enclave Execution Control", SysTEX 2017, <https://github.com/jovanbulck/sgx-step>
- Van Bulck et al., "Foreshadow", USENIX Security 2018
- Murdock et al., "Plundervolt", IEEE S&P 2020
- Borrello et al., "ÆPIC Leak", USENIX Security 2022
- Reparaz, Balasch & Verbauwhede, "Dude, is my code constant time?", DATE 2017, <https://github.com/oreparaz/dudect>
- Nilsson et al., "A Survey of Published Attacks on Intel SGX", arXiv:2006.13598
