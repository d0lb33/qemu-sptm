# qemu-sptm

Qemu with support added for emulating iPhone and Apple Silicon Mac hardware
(really anything using the Darwin kernel and Apple Silicon/ SPTM+TXM).

> [!IMPORTANT]
> This repo is not intended for direct use; rather, you should clone the main
> [`darwin-vm`](https://github.com/jprx/darwin-vm) repo, of which this repo is
> a submodule. The main [`darwin-vm`](https://github.com/jprx/darwin-vm) repo
> contains scripts required to make `qemu-sptm` actually work.

Features:
- Full support for SPTM/ TXM
- Load a custom kernelcache, SPTM, or TXM firmware, and debug any of these components
- Can boot with or without SPTM (eg. supports pre-SPTM systems too)
- SPRR/ GXF emulation (GL0-2, SPRR permission remapping)
- Many Apple specific system registers (`TAG_OFFSET_EL2`, `CTRR` regs, pseudo-PMCs) - see `scripts/darwin`
- Apple MIE/ MTE
- "Fake" hardware (good enough to fool XNU into booting): AMCC, AIC (v1, v2, and v3), CPU impl regs, SEP (invalidate hmac)
- UART/ FIQ
- APFS ramdisk / trustcache loader
- Boots with only 1 patch to the kernel and zero patches to userspace

Current limitations:
- PAC is completely disabled (see `target/arm/tcg/pauth_helper.c`) - this is ok
since we expect no PAC failures in a correctly running system anyways.
- Lockdown regs don't actually do anything (eg. `VMSA_LOCK_EL2` is a NOP) -
this is ok since a properly running system won't violate lockdown regs.
- Pro/ Max versions of CPUs are untested and probably don't work
- Multicore doesn't work (eg. `rvbar` is ignored)

## Usage

`-M darwin` is a single machine for emulating every Apple Silicon based machine
we support. It adds the following options:

```
-bootkc file     use 'file' as XNU kernelcache
-args            use 'args' as the XNU boot argument
-dtree file      use 'file' as XNU device tree
-sptm file       use 'file' as the SPTM firmware
-txm file        use 'file' as the TXM firmware
-tc file         use 'file' as the trustcache
-ramdisk file    use 'file' as the ramdisk
```

Sample invocation:

```
qemu-system-aarch64 \
  -M darwin \
  -bootkc   "firmware/bootkc" \
  -sptm     "firmware/sptm" \
  -txm      "firmware/txm" \
  -dtree    "firmware/dtree" \
  -tc       "firmware/ramdisk.tc" \
  -ramdisk  "firmware/ramdisk.dmg" \
  -args     "rd=md0 serial=3 -v -noprogress wdt=-1 wlan-olyhal-abort" \
  -nographic \
  -serial mon:stdio
```

The vision of this project is a simple easy dev environment where you provide a
kernel (possibly one you [compiled from
source](https://github.com/blacktop/darwin-xnu-build)?) and a ramdisk and are
running in seconds. This is as close to that as is possible, but you will also
need a device tree, SPTM and TXM, and trustcache to go along with your kernel
and ramdisk. The main [`darwin-vm`](https://github.com/jprx/darwin-vm) repo has
scripts to handle finding these files in an IPSW file for you.

- **Important**: The device tree *must* have been pre-processed using
`dt_fixup`, which is a script provided in the main
[`darwin-vm`](https://github.com/jprx/darwin-vm) repository.
- If your boot KC doesn't use SPTM (eg. wasn't compiled for it), just leave off
the `-sptm` and `-txm` arguments.
- The main [`darwin-vm`](https://github.com/jprx/darwin-vm) repo contains
scripts for automatically fetching and preparing these files from iOS / macOS
update files.

## Kernel patch philosophy

In a sentence, we only patch the kernel if it substantially reduces the effort
required to emulate hardware.

Ideally, we would require zero kernel patches, and nearly achieve that. We use
exactly 1 kernel patch in `AppleImage4.kext` that is automatically handled by
`hw/arm/xnu_patch.c`.

Specifically, we patch the sysctl handler `_darwin_trap_ignition_get_blob` to
return 0. This sysctl handler is called by `libignition` in `dyld` just before
running `launchd`, and will hang if we don't patch it as it waits for
`AppleImage4`'s start method to return. This method itself hangs until the
`IOAESAccelerator` is alive, which is a piece of hardware that itself requires
the IOMMU/ DART to be operational (which can be different per-SoC).

If we just patch `_darwin_trap_ignition_get_blob` to return 0 immediately, the
entire system will boot without an AES accelerator or support for the DART.
Finding this function is easy too because it's referred to by the
`security.mac.img4.ignition_blob` sysctl. `xnu_patch.c` handles this in
`patch_img4_deadlock` and was able to find and patch out this function in every
kernel collection I tried across a variety of devices.

In detail, here's the chain of function calls that is problematic:

1. dyld's dyld4::CacheFinder::CacheFinder calls ignite
2. ignite calls configuration_init, which calls sysctlbyname("security.mac.img4.ignition_blob")
3. This lands in the AppleImage4 kext (com.apple.security.AppleImage4) in _darwin_trap_ignition_get_blob
4. This calls lck_mtx_gate_wait waiting for the "blob" which is published by AppleImage4::start's call to kmod_expert_finalize
5. The kmod_expert_finalize call hangs during a call to IOService::waitForMatchingService("IOAESAccelerator")
6. This call never terminates because we don't have an aes,s8000 device (as it depends on a bunch of other stuff working)

## Is this AI slop?

No.

Every line of code in this project was written by a human (me) over a period of
around 2 months.

I did experiment with using AI tools a few times during this project, but never
let them touch the code, and eventually got frustrated with them and went back
to traditional techniques. It's possible I am just not that good of an AI
prompter, but the LLMs I tried kept going off track / getting things wrong, and
I found the workflow kind of annoying.

I found the most useful things in getting this to work were:
- reading the [XNU kernel source](https://github.com/apple-oss-distributions/xnu)
- [poking around the hardware in a hypervisor](https://github.com/jprx/gxf-playground)
- inspecting kernel core dumps of real Mac systems
- using the Virtualization.framework GDB stub to inspect a running VMAPPLE VM
- reversing SPTM/ TXM in Binja
- a little bit of trial and error

## References

A number of projects before this one worked on adding iOS / macOS support to
qemu. This project is the first to support a number of features required for
emulating newer chips (eg. SPTM/ TXM/ MIE), but builds on the knowledge of
earlier work.

Here are a collection of references I found helpful while working on this:

- [Worth Doing Badly's original blog post on emulating iOS 12 in qemu](https://worthdoingbadly.com/xnuqemu/)
- [Aleph Research's blog post on getting bash running in emulated iOS for iPhone 6S](https://alephsecurity.com/2019/06/17/xnu-qemu-arm64-1/)
- [Cyclance/ Blackberry's blog post on getting macOS 11 for the DTK to run in qemu](https://web.archive.org/web/20220705161340/https://blogs.blackberry.com/en/2021/05/strong-arming-with-macos-adventures-in-cross-platform-emulation)
- [Trung Nguyen's iPhone 11 emulation in qemu-t8030](https://github.com/TrungNguyen1909/qemu-t8030)
- [Sven Peter's writeup on SPRR/ GXF](https://blog.svenpeter.dev/posts/m1_sprr_gxf/)
- [Asahi Linux docs](https://asahilinux.org/docs/)

## About this repository

This repo is not intended for direct use; rather, you should clone this repo as
a submodule of the main [darwin-vm](https://github.com/jprx/darwin-vm) repo,
which contains required scripts (such as `dt_fixup`) and more complete
instructions for use.

This repo uses a truncated git history based on qemu `v11.1.0`; to restore the
full qemu tree history, use the following:

```
git remote add upstream https://gitlab.com/qemu-project/qemu.git
git fetch upstream
git replace 418965deef 84f07211cc
```

To reset back to truncated history, use `git replace -d 418965deef`.

For original qemu readme, see [QEMU_README.rst](QEMU_README.rst)
