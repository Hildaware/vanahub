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

For the local HorizonXI installation, `make deploy-local` builds and deploys
directly to `/Users/bferrari/Games/FFXI/HorizonXI/addons/vanahub`.
