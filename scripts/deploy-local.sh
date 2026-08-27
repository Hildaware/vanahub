#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/.." && pwd -P)"
build_dir="${repo_root}/build/win32"
package_dir="${repo_root}/dist/ffxi/addons/vanahub"
default_addons_root="/Users/bferrari/Games/FFXI/HorizonXI/addons"
addons_root="${1:-${VANAHUB_ADDONS_ROOT:-${default_addons_root}}}"

for command_name in cmake ninja i686-w64-mingw32-gcc i686-w64-mingw32-g++ rsync; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Missing required command: ${command_name}" >&2
        exit 1
    fi
done

mkdir -p "${addons_root}"
addons_root="$(cd "${addons_root}" && pwd -P)"
deploy_dir="${addons_root}/vanahub"
ashita_libs="${addons_root}/libs"

if [[ "$(basename "${addons_root}")" != "addons" || "$(basename "${deploy_dir}")" != "vanahub" ]]; then
    echo "Refusing unexpected deployment destination: ${deploy_dir}" >&2
    exit 1
fi
if [[ -L "${deploy_dir}" ]]; then
    echo "Refusing to synchronize through a symlink: ${deploy_dir}" >&2
    exit 1
fi

# Audit against the exact Ashita v4 SDK files installed at the deployment target.
if [[ -d "${ashita_libs}" ]]; then
    for module_name in common chat d3d8 imgui json; do
        if [[ ! -f "${ashita_libs}/${module_name}.lua" ]]; then
            echo "Target Ashita v4 library is missing: ${ashita_libs}/${module_name}.lua" >&2
            exit 1
        fi
    done

    imgui_annotations="${ashita_libs}/annotations/SDK/IGuiManager.lua"
    imgui_source="${ashita_libs}/imgui.lua"
    if [[ -f "${imgui_annotations}" ]]; then
        while IFS= read -r method_name; do
            if ! grep -Fq "function IGuiManager.${method_name}" "${imgui_annotations}"; then
                echo "Current Ashita v4 SDK does not expose imgui.${method_name}." >&2
                exit 1
            fi
        done < <(grep -Eo 'imgui\.[A-Za-z0-9_]+' "${repo_root}/addon/vanahub/versions/0.1.0/main.lua" | cut -d. -f2 | sort -u)
    fi
    while IFS= read -r constant_name; do
        if ! grep -Eq "^${constant_name}[[:space:]]*=" "${imgui_source}"; then
            echo "Current Ashita v4 ImGui library does not define ${constant_name}." >&2
            exit 1
        fi
    done < <(grep -Eo 'ImGui[A-Za-z0-9_]+' "${repo_root}/addon/vanahub/versions/0.1.0/main.lua" | sort -u)
    echo "Ashita v4 API audit passed for: ${addons_root}"
else
    echo "Warning: ${ashita_libs} is absent; skipping target-side Ashita v4 API audit." >&2
fi

cmake -S "${repo_root}" -B "${build_dir}" -G Ninja \
    --toolchain "${repo_root}/cmake/toolchains/windows-x86-mingw.cmake" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" --target vanahub_package

if [[ ! -f "${package_dir}/vanahub.lua" || ! -f "${package_dir}/versions/0.1.0/bin/vanahub_engine.dll" ]]; then
    echo "Build completed without the expected addon package." >&2
    exit 1
fi

mkdir -p "${deploy_dir}"
rsync --archive --delete --exclude '.DS_Store' "${package_dir}/" "${deploy_dir}/"

echo "Deployed VanaHub to: ${deploy_dir}"
echo "If Ashita is running, unload VanaHub before rebuilding and load it again afterward."
