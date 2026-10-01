# Veraison Attestation PTA

This is a proof of concept for adding attestation capabilities to S-EL0 TAs and a demonstrator of an end-to-end remote attestation protocol [1] using the Veraison verifier [2].

For convenience, this PTA reuses the PSA token format [3]. However, note that PSA semantics do not fully apply, as many relevant properties required by the PSA SM [4] are not met.

Furthermore, the attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no way to establish trust in the PTA in the first place.

For these reasons, the PTA should not be regarded as a best practice example for real-world attestation.

Instead, this PTA aims to demonstrate the integration of various libraries and tools to create a trusted application focused on attestation within the OP-TEE environment and to practically explore an end-to-end remote attestation flow using this approach.

## Signing key

By default the PTA signs with a test key embedded at build time
(`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y`). On platforms with a CAAM
(`CFG_NXP_CAAM=y`) the caller can instead pass its own key as the fourth
parameter of `PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE`: the public key
coordinates followed by the private key as a serialized CAAM key. Such a key
is a CAAM black key wrapped in a CAAM blob: it is bound to the device, the
CAAM crypto driver unwraps it inside the CAAM when signing, and the plain
private key never exists in memory. The test key can then be left out of the
build (`CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=n`).

Two commands produce such a key:

- `PTA_VERAISON_ATTESTATION_GENERATE_KEY` generates an ECDSA P-256 key pair
  in the CAAM and returns the serialized private key and the public key. The
  public key is what the verifier registers for this device.
- `PTA_VERAISON_ATTESTATION_WRAP_KEY` wraps a plain private key generated and
  registered elsewhere, for a one-time provisioning step.

The serialized key is stored by the caller (for instance in the TA's secure
storage) and handed back for every evidence. The PSA instance-id of the token
is derived from the public key of the key in use, as described in [3].

## Platform claims

With `CFG_VERAISON_ATTESTATION_PTA_PLATFORM_CLAIMS=y` the signer-id and the
security lifecycle come from the platform instead of fixed test values.
This is implemented for i.MX (`CFG_IMX_OCOTP=y`): the signer-id is the SRK
hash fused into the OCOTP, that is the hash of the keys the HAB secure boot
verifies the boot images against, and the lifecycle is derived from the SRK
and SEC_CONFIG fuses (no SRK hash: assembly and test; SRK hash on an open
device: PSA RoT provisioning; closed device: secured).

## Known Limitations

1. **PSA Semantics Limitations:** Although this PTA reuses the PSA token format, many of the relevant properties required by the PSA Security Model (SM) are not met. This can impact the effectiveness and security assumptions typically expected from PSA-based attestation.

2. **Lack of Trust in the PTA:** The attestation evidence produced by the PTA attests to the memory contents of the calling TA, but there is no mechanism to establish trust in the PTA itself from a lower-level entity, such as the bootloader. Without such anchoring to a platform Root of Trust (RoT), the PTA lacks foundational trust, which weakens the overall chain of trust. A CAAM-held signing key and the fuse-derived claims tie the evidence to the device and to its secure boot configuration, but they do not measure the PTA or OP-TEE itself.

## References

[1] https://datatracker.ietf.org/doc/rfc9334
[2] https://github.com/veraison/services
[3] https://datatracker.ietf.org/doc/draft-tschofenig-rats-psa-token
[4] https://www.psacertified.org/app/uploads/2021/12/JSADEN014_PSA_Certified_SM_V1.1_BET0.pdf
