cmake_minimum_required(VERSION 3.24)
project(vanahub VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(VH_BUILD_ENGINE "Build the Win32 x86 package engine DLL" ${WIN32})
option(VH_BUILD_TESTS "Build native tests" ON)

add_library(vanahub_core STATIC
    native/src/core.cpp
)
target_include_directories(vanahub_core PUBLIC native/include)
target_compile_features(vanahub_core PUBLIC cxx_std_20)

add_executable(vanahub_settings_scan tools/settings_scan.cpp)
target_link_libraries(vanahub_settings_scan PRIVATE vanahub_core)

if(VH_BUILD_ENGINE)
    if(NOT WIN32)
        message(FATAL_ERROR "The package engine targets Win32 only")
    endif()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "The package engine must be compiled for x86/Win32")
    endif()

    include(FetchContent)
    set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Do not update fetched dependencies during rebuilds" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build dependencies statically" FORCE)
    set(MZ_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(MZ_BUILD_UNIT_TESTS OFF CACHE BOOL "" FORCE)
    set(MZ_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(MZ_COMPAT OFF CACHE BOOL "" FORCE)
    set(MZ_BZIP2 OFF CACHE BOOL "" FORCE)
    set(MZ_LZMA OFF CACHE BOOL "" FORCE)
    set(MZ_ZSTD OFF CACHE BOOL "" FORCE)
    set(MZ_PKCRYPT OFF CACHE BOOL "" FORCE)
    set(MZ_WZAES OFF CACHE BOOL "" FORCE)
    set(MZ_OPENSSL OFF CACHE BOOL "" FORCE)
    set(MZ_LIBCOMP OFF CACHE BOOL "" FORCE)
    set(ZLIB_REPOSITORY https://github.com/zlib-ng/zlib-ng.git CACHE STRING "" FORCE)
    set(ZLIB_TAG 12731092979c6d07f42da27da673a9f6c7b13586 CACHE STRING "Pinned zlib-ng 2.3.3 commit" FORCE)
    set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
    FetchContent_Declare(minizip_ng
        GIT_REPOSITORY https://github.com/zlib-ng/minizip-ng.git
        GIT_TAG f3ed731e27a97e30dffe076ed5e0537daae5c1bd)
    FetchContent_MakeAvailable(minizip_ng)

    FetchContent_Declare(monocypher
        GIT_REPOSITORY https://github.com/LoupVaillant/Monocypher.git
        GIT_TAG 0d85f98c9d9b0227e42cf795cb527dff372b40a4)
    FetchContent_GetProperties(monocypher)
    if(NOT monocypher_POPULATED)
        FetchContent_Populate(monocypher)
    endif()
    add_library(monocypher STATIC
        "${monocypher_SOURCE_DIR}/src/monocypher.c"
        "${monocypher_SOURCE_DIR}/src/optional/monocypher-ed25519.c")
    target_include_directories(monocypher PUBLIC
        "${monocypher_SOURCE_DIR}/src"
        "${monocypher_SOURCE_DIR}/src/optional")

    add_library(vanahub_engine SHARED native/src/engine.cpp native/exports.def)
    target_include_directories(vanahub_engine PRIVATE native/include ${minizip_ng_SOURCE_DIR})
    target_link_libraries(vanahub_engine PRIVATE vanahub_core MINIZIP::minizip monocypher winhttp bcrypt ws2_32)
    target_compile_definitions(vanahub_engine PRIVATE VH_ENGINE_BUILD WIN32_LEAN_AND_MEAN NOMINMAX)
    set_target_properties(vanahub_engine PROPERTIES OUTPUT_NAME "vanahub_engine" PREFIX "")
    if(MINGW)
        target_link_options(vanahub_engine PRIVATE -static -static-libgcc -static-libstdc++ -Wl,--kill-at)
        add_custom_command(TARGET vanahub_engine POST_BUILD
            COMMAND ${CMAKE_STRIP} "$<TARGET_FILE:vanahub_engine>"
            COMMENT "Stripping Win32 release symbols")
    endif()

    set(VH_DIST_ROOT "${CMAKE_SOURCE_DIR}/dist/ffxi" CACHE PATH
        "Stable output root for the deployable FFXI runtime")
    set(VH_PACKAGE_DIR "${VH_DIST_ROOT}/addons/vanahub")
    add_custom_target(vanahub_package ALL
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_SOURCE_DIR}/addon/vanahub
            -DDEST_DIR=${VH_PACKAGE_DIR}
            -P ${CMAKE_SOURCE_DIR}/cmake/publish-addon.cmake
        COMMAND ${CMAKE_COMMAND} -E make_directory "${VH_PACKAGE_DIR}/versions/0.1.0/bin"
        COMMAND ${CMAKE_COMMAND} -E rm -f "${VH_PACKAGE_DIR}/versions/0.1.0/bin/.gitkeep"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:vanahub_engine>" "${VH_PACKAGE_DIR}/versions/0.1.0/bin/vanahub_engine.dll"
        DEPENDS vanahub_engine
        COMMENT "Publishing the Ashita addon to ${VH_PACKAGE_DIR}")
endif()

if(VH_BUILD_TESTS)
    enable_testing()
    add_executable(vanahub_core_tests tests/native/core_tests.cpp)
    target_link_libraries(vanahub_core_tests PRIVATE vanahub_core)
    if(MINGW)
        target_link_options(vanahub_core_tests PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
    add_test(NAME vanahub_core_tests COMMAND vanahub_core_tests)
    if(VH_BUILD_ENGINE)
        add_executable(vanahub_engine_tests tests/native/engine_tests.cpp)
        target_include_directories(vanahub_engine_tests PRIVATE native/include)
        target_link_libraries(vanahub_engine_tests PRIVATE vanahub_engine bcrypt)
        if(MINGW)
            target_link_options(vanahub_engine_tests PRIVATE -static -static-libgcc -static-libstdc++)
        endif()
        add_test(NAME vanahub_engine_tests COMMAND vanahub_engine_tests)
    endif()
endif()
