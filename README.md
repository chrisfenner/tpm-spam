# tpm-spam
Semantic Platform Attestation Measurements

## Objective
Facilitate predictive TPM sealing with meaningful abstractions.

## Background
TPMs contain PCRs, which are arrays of 24 hash values. Software, configuration,
and well-meaning commentary are measured into PCRs by the boot stack on modern
computer systems. On a typical PC with UEFI, there are on the order of 100
measurements into the various PCRs.

Users of TPM may want to predictively seal data to expected PCR values. TPM
technically allows this, but PCRs don't make it easy. TCG defines a
[specification](https://trustedcomputinggroup.org/resource/tcg-efi-platform-specification/)
for the various measurements that EFI platforms should make so that firmware
and software code and configuration are accurately depicted in the PCRs for
explicit attestation by verifying a TCG log.

On modern PCs, most PCRs are too brittle to reliably predictively seal data against.
Some unforeseen minor configuration change or phase of the moon may cause
software to extend different data into a PCR from one boot to the next, or the
data being extended might be a counter that is intended to change from one boot
to the next.

## Spam
Spam = "**S**emantic **P**latform **A**ttestation **M**easurements"

A spam is an object in TPM memory that can only be overwritten after a reboot.
This object can be referenced in TPM policies, for example, policies on sealed
data.
Spam is implemented on current TPMs by use of NV (nonvolatile) objects, with
NV attributes that make them not-so nonvolatile. The spec calls these "Hybrid" indices.
* `TPMA_NV_ORDERLY` indicates this index can be cached in RAM until clean shutdown, and also causes 
  `TPMA_NV_WRITTEN` to be cleared on TPM Reset (cold reboot).
* `TPMA_NV_CLEAR_STCLEAR` clears the `TPMA_NV_WRITTEN` bit even on TPM Restart (warm reboot).
* An index with `TPMA_NV_WRITTEN` cleared may as well not have data in it.
  * Calls to `TPM2_NV_Read` and `TPM2_PolicyNV` fail if the index is not written, returning
    `TPM_RC_NV_UNINITIALIZED`.
* NV index size is 64 bytes, which is enough for a 256-bit hash (e.g., a verification key used to
* verify some signature containing the boot stage's code plus metadata) and 256 bits of metadata
* (e.g., some opaque hash of something else, four 64-bit version fields, a 32-character ASCII
* string, or some combination of semantically meaningful data for versioned policy assertions).

## Compatibility
Spam depends only on features in
[the current TPM spec](https://trustedcomputinggroup.org/resource/tpm-library-specification/),
but the spec calls out that hybrid NV index support is not mandatory for all TPMs:
[Part 1: revision 1.59](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf)
says in particular in section 32.7 (NV Indices):

> An implementation is not required to support an arbitrary number of hybrid indices and is not
> required to support any ordinary hybrid index with a size of more than eight octets.

Spam uses TPMA_NV_ORDERLY to avoid wasted NV write cycles on each boot. However, to maintain
the desired security properties (spams reset on reboot), `TPMA_NV_CLEAR_STCLEAR` would be
sufficient in a modified spam implementation on TPMs that don't support larger ordinary hybrid
indices.

## Threat Model
Spams have a policy that allows writes only when `TPMA_NV_WRITTEN` is cleared, so they are
write-once-per-boot. This means that whichever piece of code on a system writes a particular spam
first, wins.

For technical reasons to do with the limitations of TPM NV indices, initializing spams requires
Platform authorization, which is reset to the Empty auth on reboot and intended to be set to a
random value and discarded by the system firmware.

Spam assumes that the software initializing all the spams is extended into PCR[00]. Fixing a bug or
vulnerability in that software should be reflected in PCR[00], and any policy that depends on spams
should also depend on PCR[00].

Each boot phase after spam initialization should be measured into a spam before being launched.
Failure to measure a spam should cause the invalidation of PCR[00]. This prevents a piece of
software from modifying its own spam. Note that because spams are all defined (but not written) at
the beginning of the boot, measuring a spam is simply a write to an NV index that already exists
and has space in memory already allocated to it. The chain of measurements starts with the Root of
Trust for Measurement (RTM) in PCR[00] and extends through the boot chain as reflected in the spams.

After boot, the boot chain is reflected into PCR[00] and a collection of spams, e.g.:
* PCR[00]: BIOS (form: a hash of hashes)
* SPAM: Bootloader (form: hash of key used to verify GRUB || GRUB version)
* SPAM: Kernel (form: hash of key used to verify kernel || kernel version)
* SPAM: Kernel command-line (form: hash of cmdline)

Spam allows policy authors to reference semantic measurements of code depending on the format of
the particular spam being referenced. For example, a kernel spam policy could require a particular
kernel verification key hash (e.g., the first 32 bytes of the spam) and a minimum major kernel
version (e.g., the next 4 bytes of the spam interpreted as a uint). This would allow secrets sealed
for a particular kernel to still be unsealable by an updated kernel (signed by the same key), while
allowing future secrets sealed to that kernel not to be unsealable by a rolled-back kernel. 

The index space of spam is much sparser than PCRs: 16 bits or 65536 possible spams. Each spam index
should be unique per purpose, and encode stable formatting semantics.