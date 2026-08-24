# VanaHub — Master Plan

## Product

Build VanaHub as a Lua/ImGui package-browser frontend, a Win32/x86 native worker DLL, and
a separate signed public catalog with automated admission. V1 installs stable
Ashita v4 Lua addons only. Downloads and updates are always user initiated.

## Security contract

- Built-in packages are restricted to statically analyzable Lua without FFI,
  networking, process execution, arbitrary filesystem writes, memory writes,
  packet injection, native code, dynamic evaluation, or self-updating logic.
- Custom repositories require a repository warning and per-artifact consent
  for elevated findings. Structurally unsafe archives are always rejected.
- Every artifact is SHA-256 pinned. The built-in index is Ed25519 signed.
- Installation is staged, journaled, validated, and rolled back on failure.
- “Screened” means automated checks passed; the UI never calls code “safe.”

## Delivery sequence

1. Establish schemas, scanner policy, hostile test corpus, and public ABI.
2. Implement the shared scanner and asynchronous native engine.
3. Implement the Lua frontend, state store, custom repositories, and consent.
4. Deploy the separate catalog admission, signing, and revocation workflows.
5. Harden with fuzzing, Windows/Wine integration, recovery tests, and beta use.

Detailed behavior and acceptance criteria live alongside the implementation in
`docs/` and the versioned files under `schemas/` and `policy/`.
