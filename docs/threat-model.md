# Threat model

## Protected assets

- The user's Ashita installation and addon configuration.
- Files and credentials accessible to the FFXI process.
- The integrity and availability of FFXI/Ashita.
- Catalog signing keys and the catalog repository.

## Adversaries

- A malicious package author or compromised maintainer account.
- A malicious custom repository.
- A mutable or replaced third-party release asset.
- A crafted ZIP exploiting traversal, collisions, expansion, or parser bugs.
- A pull request attempting to compromise catalog automation.

## Boundaries

Catalog artifacts are always untrusted data. CI never imports, executes, builds,
or tests submitted addon code. The client never installs directly from an
archive: it downloads, hashes, scans, stages, validates, and then commits.

Static analysis cannot prove arbitrary Lua harmless. The built-in repository
therefore accepts only a restricted, intentionally analyzable Lua profile.
Custom repositories remain an explicit trust decision. Path traversal, unsafe
archive structure, size abuse, hash mismatch, and signature failure are hard
blocks that cannot be overridden.

## Built-in prohibited behavior

- Network clients, sockets, uploads, or downloads.
- Process creation, shell execution, or persistence.
- FFI, native modules, dynamic libraries, executables, or scripts.
- Dynamic evaluation, bytecode, obfuscation, or computed module loading.
- Arbitrary file modification, registry access, memory writes, packet
  injection/modification, and self-installation.

The package manager's own signed release is the sole native-code exception:
package id `xirepo` may contain exactly `bin/xirepo_engine.dll`. The client
stages it in a versioned directory and activates it only on the next launch.
