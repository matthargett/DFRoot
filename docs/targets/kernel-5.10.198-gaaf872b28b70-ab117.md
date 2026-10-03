# `kernel-5.10.198-gaaf872b28b70-ab117`

This exact-release module target exists for a non-KMI kernel whose release
string does not contain an `androidNN` generation. It does not weaken module
selection to a kernel prefix.

## Exact identity

- Kernel release: `5.10.198-perf-gaaf872b28b70-ab117`
- Module size: `9888` bytes
- Module SHA-256: `50ea42a2fc38ca3a3e92c142be6576a0bdf0a41f6c3b93819506225716c06a35`
- Module vermagic: `5.10.198-perf-gaaf872b28b70-ab117 SMP preempt mod_unload modversions aarch64`
- Completion contract: make SELinux permissive, return an error so the module
  unloads, then continue with an exact init-shell target

This target is live verified. Starting from SELinux enforcing, the exact image
loaded through the privileged module-loader path, changed SELinux to
permissive, and self-unloaded. Cleanup reported `restored_exact` for the module
carrier, bridge, and C++ runtime. The independently guarded init-shell follow-up
then produced a UID 0 command channel. The entire result was reproduced after a
clean reboot.

This image is selected only by the full kernel release. Other 5.10 kernels must
provide their own exact image or satisfy one of the existing KMI identities.
