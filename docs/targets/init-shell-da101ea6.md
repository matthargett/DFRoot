# `init-shell-da101ea6`

## Evidence state

The composed target was live verified on the exact build. It produced a UID 0
command channel with group `shell`, full effective capabilities, the `shell`
SELinux domain, and SELinux still enforcing. The app reported exact hook
restoration, and the complete carrier hash matched again after reboot.

This target does not change the identity of `adbd`; a new ADB session remains
UID 2000. Callers must report the command channel and daemon identities
separately.

## Identity

- Kernel release: `4.19.81-perf+`
- Carrier: `/system/lib64/libc++.so`
- Carrier SHA-256: `da101ea6af2028a77f460ec9166e290c771d9cc2a21dce3c269c83b283c4fba8`
- Hook symbol: `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`
- Observed hook offset in the exact carrier: `0x7d61c`
- Observed payload cave offset in the exact carrier: `0xc4180`

The runtime hashes the complete carrier before resolving the symbol and code
cave. It does not reuse these observed offsets as a fallback when the hash or
kernel release differs.

## Runtime result

The hook runs only in UID 0, TID 1. It forks a child, changes the child's group
to `shell`, requests the `shell` execution context, and passes the embedded
command directly to `/system/bin/sh -c`. It does not depend on an externally
staged script or ask the `init` domain to create a `shell_data_file`. The
channel exposes its status at `/data/local/tmp/dfroot-shell/status` and sets
`debug.dfroot.ready=1` only after setup succeeds.

The payload records separate failure markers for group change, SELinux
transition, and `execve`. Channel setup failures publish the exact shell step
and exit status through `debug.dfroot.error`. `/dev/dfs` guards the one-shot
init path; a repeated attempt reports that a reboot is required before any
patch is installed. The hook payload and trampoline are preserved before the
write, restored after the trigger, evicted from the file cache, and checked
against their original bytes.

## Live acceptance

1. Kernel release and complete carrier SHA-256 matched.
2. The channel reported UID 0, GID 2000, full effective capabilities, and
   `u:r:shell:s0`.
3. The app reported `restored_exact` for the payload and trampoline.
4. A reboot returned the original complete carrier SHA-256 and cleared the
   temporary channel.
