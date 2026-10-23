# Resources

## Research
- [SGX-Step](https://github.com/jovanbulck/sgx-step)
- [SGX.Fail](https://sgx.fail)
- Survey of Published Attacks on Intel SGX, arXiv:2006.13598
- Intel SGX Explained, IACR ePrint 2016/086

## Platforms and tooling
- [Intel DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives), [Gramine](https://gramine.readthedocs.io), [Occlum](https://github.com/occlum/occlum)
- [AMD SEV](https://www.amd.com/en/developer/sev.html), [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [NVIDIA confidential computing](https://docs.nvidia.com/confidential-computing/)

## Standards
- IETF RATS, [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)
- [Confidential Computing Consortium](https://confidentialcomputing.io)

## Side-channel testing
- [dudect](https://github.com/oreparaz/dudect): statistical constant-time testing (Reparaz et al., DATE 2017)
- Xu, Cui & Peinado, "Controlled-Channel Attacks: Deterministic Side Channels for Untrusted Operating Systems", IEEE S&P 2015
- Murdock et al., "Plundervolt", IEEE S&P 2020; Borrello et al., "ÆPIC Leak", USENIX Security 2022

## Attestation tooling
- [VirTEE snpguest](https://github.com/virtee/snpguest): SEV-SNP report fetch and verification
- AMD SEV-SNP ABI specification (report layout), via the [AMD SEV developer page](https://www.amd.com/en/developer/sev.html)
- [NVIDIA nvtrust](https://github.com/NVIDIA/nvtrust): GPU attestation tools and samples
- [Intel SGX SDK for Linux](https://github.com/intel/linux-sgx) (EDL, simulation mode)

## Rollback and enclave runtimes
- Matetic et al., "ROTE: Rollback Protection for Trusted Execution", USENIX Security 2017
- Van Bulck et al., "A Tale of Two Worlds: Assessing the Vulnerability of Enclave Shielding Runtimes", ACM CCS 2019
- Checkoway & Shacham, "Iago Attacks", ASPLOS 2013

## Platforms
- [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/)
