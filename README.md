# VanaHub

VanaHub is a secure, Dalamud-style addon browser and delivery system for
Ashita v4.

The product has two runtime parts:

- `addon/`: Lua/ImGui frontend loaded by Ashita v4.
- `native/`: Win32/x86 worker DLL and shared native validation core.

The signed public catalog is maintained independently in
[`Hildaware/vanahub-catalog`](https://github.com/Hildaware/vanahub-catalog).
This repository retains the shared validation and signing-policy tools pinned
by that catalog's automation.

The built-in catalog is deliberately restrictive. Passing its automated scan
means only that the artifact complied with the published policy; it is not a
guarantee that arbitrary executable Lua is safe.

See [PLAN.md](PLAN.md), [docs/threat-model.md](docs/threat-model.md), and
[docs/development.md](docs/development.md).

Build the macOS cross-compiled package with:

```sh
cmake -S . -B build/win32 -G Ninja \
  --toolchain cmake/toolchains/windows-x86-mingw.cmake
cmake --build build/win32 --target vanahub_package
```

The result is always published to `dist/ffxi/addons/vanahub`, independent of
the CMake build directory. This is the directory to share with a Steam Deck
using Syncthing. The built-in catalog is
pinned to its GitHub Pages index and Ed25519 verification key in
`addon/vanahub/versions/0.1.0/builtin.lua`.
At runtime, VanaHub loads its last verified catalog cache immediately and
refreshes the signed remote catalog in the background on startup. Built-in
catalog icons and screenshots are downloaded lazily, verified against their
content-addressed filenames, and cached under VanaHub's configuration cache.

## Managed startup

Add only VanaHub to the Ashita startup script:

```text
/addon load vanahub
```

The Installed tab provides named profiles, per-addon Auto-load checkboxes, and
load-order controls. VanaHub loads the active profile one addon at a time after
its verified local catalog-cache check finishes. Load and Unload affect only
the current session; Auto-load changes the next startup. Ordering applies only
to addons managed by VanaHub, not to other entries left in Ashita's scripts.

Profiles can be exported as `.vanahub-profile.zip` files from the Installed
tab. An export contains profile order and auto-load state, catalog source and
version metadata, and optionally each addon's on-disk configuration directory;
it never contains addon binaries or VanaHub's own configuration. Settings are
selected per addon and scanned by content rather than by a fixed extension
list, allowing uncommon text formats and recognized UI media while rejecting
executables, general-purpose scripts, nested archives, unsafe Lua, links, and
unrecognized binary data.
The embedded manifest format is documented by
[`schemas/profile.schema.json`](schemas/profile.schema.json).
Exports are written to `config/addons/vanahub/profiles/exports` using the
filename entered in the ImGui panel; VanaHub asks before replacing an existing
archive and does not invoke a native operating-system file dialog.

Import inspects the complete archive before showing a review. Missing addons
can be installed from the current built-in release or an explicitly trusted
custom repository carried by the profile. Existing settings are backed up and
replaced only after affected addons unload. Unavailable or failed addons remain
visible in the new profile with auto-load disabled. Profile files are not
signed: only import profiles from people you trust, and inspect the review for
private settings and custom repository URLs.
To import, paste a full archive path into the ImGui panel, or copy the file into
`config/addons/vanahub/profiles/imports` and enter only its filename.

For the local HorizonXI installation, `make deploy-local` builds and deploys
directly to `/Users/bferrari/Games/FFXI/HorizonXI/addons/vanahub`.
