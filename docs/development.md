# VanaHub development

## Requirements

- CMake 3.24+
- Ninja
- C++20 compiler
- Python 3.11+
- Lua 5.1-compatible interpreter for frontend syntax tests
- MinGW-w64 `i686-w64-mingw32` toolchain for macOS cross-builds
- Visual Studio 2022 x86 tools for release builds

## Configure native tests

```sh
cmake -S . -B build/native -G Ninja -DVH_BUILD_ENGINE=OFF
cmake --build build/native
ctest --test-dir build/native --output-on-failure
```

## Cross-compile the DLL

```sh
cmake -S . -B build/win32 -G Ninja \
  --toolchain cmake/toolchains/windows-x86-mingw.cmake
cmake --build build/win32 --target vanahub_package
```

The deployable tree is always published to `dist/ffxi/addons/vanahub`, even
when a different CMake build directory is used. Because this directory contains
only the assembled FFXI addon runtime, it can be used directly as a Syncthing
folder with the Deck's `addons/vanahub` directory as the destination. Package
rebuilds preserve Syncthing's `.stfolder` marker and an optional `.stignore`.
Configure `addon/vanahub/versions/0.1.0/builtin.lua` only after the separate
catalog repository and its Ed25519 key have been created.

## Build and deploy to HorizonXI

From the repository root, run:

```sh
make deploy-local
```

This builds the Release package and synchronizes it to
`/Users/bferrari/Games/FFXI/HorizonXI/addons/vanahub`. The destination is made
to exactly match the generated package, so unload the addon before deploying.
Before building, the script audits the frontend's required modules, ImGui
methods, and flag constants against that installation's bundled Ashita v4 SDK.

To deploy to a different Ashita installation:

```sh
make deploy-local DEPLOY_ROOT=/path/to/ashita/addons
# or
./scripts/deploy-local.sh /path/to/ashita/addons
```

## Catalog scanner

The public index, package manifests, and admission workflows live in the
separate [`Hildaware/vanahub-catalog`](https://github.com/Hildaware/vanahub-catalog)
repository. This product repository owns the shared scanner and signing-policy
tools that catalog automation pins to reviewed product commits.

```sh
python3 -m unittest discover -s tests/python -v
python3 tools/catalog_scan.py package.json --output scan-report.json
```

## Frontend tests

The profile state and migration logic is independent of Ashita and can be
tested with any Lua 5.1-compatible interpreter:

```sh
lua tests/lua/test_profiles.lua
luac -p addon/vanahub/vanahub.lua addon/vanahub/versions/0.1.0/*.lua
```

The Win32 engine tests also exercise portable-profile ZIP export, verified
catalog-profile download, staged inspection, content-based settings scanning,
and backup/replace restoration.

The Windows ABI smoke test runs in Product CI. It can also run under a Wine
prefix that includes 32-bit/WoW64 support; a 64-bit-only Wine prefix cannot
launch the PE32 test binary.
