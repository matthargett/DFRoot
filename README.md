> [!IMPORTANT]
> If you want to use your own ksud binary, you must compile from my fork: https://github.com/diabl0w/KernelSU

# DFRoot [DirtyFrag (CVE-2026-43284)]

The core of this code is fully credited to others. I merely combined ideas to make them all better 
and added some small improvements/features. 

Credits:
- Original PoC and various code: https://github.com/lsposed/lspromise
- Selinux Permissive kernel modules and various code: https://github.com/polygraphene/DFReroot
- Unprivileged XFRM socket method: https://github.com/combeng6th/DirtyInit

## Features

- Start on Boot
- Automatic soft reboot 
- RO Partition Protection
- Hide Selinux Modifications in KSU
- Shizuku not needed — regain root without WiFi!

> [!WARNING]
> I am not responsible for any damage to your device.

## Supported Devices

Ephemeral root for Samsung devices (and possibly others) w/ locked bootloaders vulnerable to DirtyFrag (CVE-2026-43284) 

| KMI Version | Verified |
|---|---|
| android12-5.10 | Yes |
| android13-5.10 | Untested |
| android13-5.15 | Yes |
| android14-5.15 | Untested |
| android14-6.1 | Not working - [accidental mitigation](https://github.com/V4bel/dirtyfrag/issues/23#issuecomment-4405314290) |
| android15-6.6 | Yes |
| android16-6.12 | Yes |
| android17-6.18 | Untested |

### Runtime compatibility

The app selects one exact strategy at runtime:

1. A bundled module first matches an exact full kernel release when one is
   declared, then falls back to an exact Android KMI generation plus kernel
   major/minor match. A same-version module from another KMI is rejected.
2. An init hook target is selected by kernel release, carrier path, carrier
   SHA-256, and hook symbol. It starts a UID 0 command channel without a module.
3. A protected daemon target is selected by kernel release and an exact bridge
   identity, then checked through protected build-ID, file-end, and patch
   preimage blocks before any target byte is changed.
4. An external direct-kernel provider is selected by exact device, fingerprint,
   security patch, build incremental, kernel release, provider SHA-256, and any
   declared physical PFN envelope.
   Its dry probe must emit every declared offset marker before a live attempt.
   The descriptor also declares whether the proven execution domain is the app
   or ADB shell; the app does not retry a provider in a domain that cannot meet
   its prerequisites.

Every userspace patch is read back after application and restored in reverse
order. The module path records the full bridge and carrier identities before
its first write, evicts both modified cache entries during cleanup, and rejects
cleanup unless both identities match again. Output distinguishes a matched
candidate, exact byte validation, an armed trigger window, verified
restoration, and the separate UID/context check required to prove root.

### Native layout

The exploit is composed from small layers with one level of responsibility:

| Layer | Responsibility |
|---|---|
| `dirtyfrag_writer.c` | CBC page-cache writes and protected-file bridge I/O |
| `elf_hook.c` | Reversible ELF payload and trampoline transaction |
| `patch_window.c` | Guard, apply, trigger window, reverse restore, and result state |
| `payloads.c` | Embedded helpers, exact module selection, and completion contracts |
| `target_registry.c` | Runtime identity matching and actionable rejection output |
| `targets/*.c` | One declarative firmware target per source file |
| `root_runtime.c` | Module and init strategy orchestration |
| `exp.c` | JNI boundary and strategy composition |
| `DirectKernelRegistry.java` | Exact external-provider identity and hash selection |
| `PhysicalMemoryProbe.java` | Runtime PFN-envelope derivation and comparison |
| `DirectKernelRunner.java` | Dry markers, bounded attempts, and result markers |
| `DirectKernelShellLauncher.java` | Generated shell-domain guards and execution |
| `RootService.java` | Foreground lifetime and durable per-operation report |

To add a build, create one file under `app/src/main/jni/targets/`, add it to
the native source list, and add one line to `targets/targets.inc`. Do not add a
looser version fallback.
Record the exact kernel release, full carrier or bridge SHA-256, protected
build ID, aligned preimage/replacement blocks, and the observed trigger. A
target is live verified only after a fresh shell reports UID 0 and the app
reports exact restoration. An offline-derived descriptor must say so until
that test is completed.

Current declarative userspace targets:

| Target | Evidence state |
|---|---|
| `init-shell-da101ea6` | Composed target live verified a UID 0 command channel and exact restoration |
| `init-shell-10db7caf` | Live verified a UID 0 command channel and exact restoration |
| `kernel-5.10.198-gaaf872b28b70-ab117` + `init-shell-10db7caf` | Live verified from enforcing state and reproduced after a clean reboot |
| `adbd-fd30e626` | Live verified UID 0 daemon and exact restoration |
| `adbd-e52b5144` | Exact offline kernel and userspace analysis; live chain untested |
| `android10-4.4.205-49845030443200410` | Live verified fresh UID 0 ADB shell through the generated shell-domain launcher |

## How it works

The Android kernel decrypts AES-CBC ESP packets directly into the page cache of files open for `splice()`. By crafting `IV = AES_ECB_DEC(key, current_content) ⊕ desired_content`, any 16-byte-aligned block in a mapped shared library can be overwritten without write permission and without copy-on-write.

The exploit uses this primitive to patch shellcode into `libc++.so` in the kernel's page cache. The next privileged call to the hooked function runs the shellcode, which loads our custom kernel module via `insmod`. 

### Exploit chain

1. **IpSec transform** — App allocates a `UdpEncapsulationSocket` + SPI and builds an AES-CBC/HMAC-SHA256 ESP transform via `IpSecManager`.

2. **splicehelper → crash_dump64** — The splicehelper binary is spliced into `crash_dump64` via the CBC primitive. `crash_dump64` runs in the `crash_dump` SELinux domain (via exec label transition), which can open `vendor_file` labeled files (untrusted_app context cannot read these files so we need this bridge). The helper can splice a 16-byte page chunk, read one block for IV computation, stream a protected file for identity hashing, or drop its clean cache pages.

3. **dirtyfrag.ko → vendor_file** — The kernel module is written via the crash_dump bridge (splicehelper splice mode) into a `vendor_file`-labeled file

4. **libc++ hook** (fires in init, uid=0, tid=1) — Shellcode is patched into `libc++.so` at `std::ostream::sentry::sentry()` (`_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`). Triggered by: `createOrphanProcess()` double-forks so the grandchild is adopted by PID 1 (init); when init reaps the orphan its main thread (tid=1) calls through the hooked function. The shellcode:
   - Checks `getuid()==0` and `gettid()==1`; returns immediately otherwise
   - Creates `/dev/df` as a one-shot mutex (O_CREAT|O_EXCL) to prevent re-entry
   - Clones a worker child (parent returns to init immediately)
   - Worker forks a grandchild; grandchild writes `u:r:vendor_modprobe:s0` to `/proc/self/attr/exec` then execs `/vendor/bin/insmod <ko_target>`

5. **Module completion** — Each exact module image declares what successful
   initialization provides. Existing KMI images launch `ksud`. An exact-release
   image may instead make SELinux permissive, self-unload, and continue into a
   separately guarded init-shell target.

6. **Cleanup** — The libc++ hook is restored, the module
   carrier and `crash_dump64` are evicted from cache, and their pre-write
   identities are checked again.

7. **Optional init-shell follow-up** — A module whose completion contract only
   changes policy is followed by the independently selected init-shell target.
   That hook is restored and checked through the same ELF transaction.

## Usage

Install KernelSU Manager (download & unzip manager file) from actions flow: 
https://github.com/tiann/KernelSU/actions/runs/35973514328

```sh
./build.sh
adb install -r dirtyfrag.apk
```

The UI runs the selected strategy. For an ADB driven run, the shell-only
service keeps the restoration watchdog in the foreground:

```sh
adb shell am start-foreground-service -n df.root/.RootService
```

Run only the read-only strategy and offset probe with:

```sh
adb shell am start-foreground-service -n df.root/.RootService \
  --ez df.root.extra.PROBE_ONLY true
adb shell run-as df.root cat \
  /data/user_de/0/df.root/files/last-operation.log
```

When an exact descriptor requires the ADB shell domain, the probe writes and
prints one launcher command. The generated script rechecks the running build,
provider SHA-256, shell-visible PFN envelope, and all dry-probe markers. Whole
attempts repeat only after the provider's exact clean allocator-exhaustion
marker. A fresh `adb shell` must still prove UID, context, SELinux state, and
the `adbd` credential change.

Direct-kernel provider binaries are not committed by this project. Their local
filenames are ignored by default. Obtain an exact provider under compatible
terms, verify the descriptor's SHA-256, and package it in the declared
`jniLibs/arm64-v8a` path. A build without that exact file reports the missing
provider and does not substitute another binary.

Boot startup delegates to the same foreground service and requests only an
unattended strategy. A target that needs a host-side daemon restart is
reported as interaction-required and is not armed during boot.

For an interactive daemon target, watch `files/root-state.txt` with `run-as`.
When it reports `state=armed`, restart that daemon from the host, reconnect,
and verify both `id` and `id -Z`. `state=restored` proves the page-cache cleanup;
it does not by itself prove the new daemon ran as UID 0.
