# Carrier provider notice

The bundled provider is built from upstream revision
`2324ce262e674504ad41ec82abcda3bf09dd01e6` under the adjacent MIT license.

The Android build uses the upstream local execution path with these packaging
changes:

- the Java helper package is renamed to `df.provider`;
- user-visible help text and temporary paths use generic provider terms;
- persistent root payload assets are omitted because this adapter requests
  transient ADB root only; and
- compiler paths are remapped out of the stripped release binary.

The descriptor records the provider and every runtime input by SHA-256. The
generated launcher copies them to a private temporary directory, hashes the
copies again, and refuses a live run when any value differs.
