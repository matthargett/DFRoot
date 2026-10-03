# `init-shell-10db7caf`

This descriptor matches one exact init-loaded C++ runtime and never falls back
to a model, vendor, Android release, or kernel-prefix guess.

## Exact identity

- Kernel release: `5.10.198-perf-gaaf872b28b70-ab117`
- Carrier: `/system/lib64/libc++.so`
- Carrier size: `762856` bytes
- Carrier SHA-256: `10db7caff0bfff13c463a5b94841f923b6a895bb0c5608e40572b8463d6b4613`
- Hook symbol: `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_`
- Observed symbol file offset: `0x68cac`
- Patched hook file offset after the PAC/BTI landing instruction: `0x68cb0`
- Observed payload file offset: `0xb17a8`

The carrier build ID was observed as
`01e7ac396acbf9c9ebe0793d2b7d71f5`. The full-file SHA-256 remains the runtime
selection guard.

An initial permissive-boot run exposed a stale FIFO channel left by an older
build. A subsequent enforcing run also found one 16-byte restoration packet
whose UDP send completed without changing the cache. The shared channel now
uses `/data/local/tmp/dfroot-command`, and every ELF write has exact readback
with targeted repair of mismatched 16-byte blocks.

## Evidence state

This target is live verified. Starting from SELinux enforcing, the composed
strategy matched the exact carrier, reported exact payload and trampoline
readbacks, and created a fresh command channel reporting `uid=0`, `gid=2000`,
and `u:r:shell:s0`. Cleanup reported `restored_exact` for the carrier. The same
result was reproduced after a clean reboot while ADB itself remained UID 2000.
