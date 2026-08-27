.PHONY: package deploy-local

package:
	cmake -S . -B build/win32 -G Ninja \
		--toolchain cmake/toolchains/windows-x86-mingw.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build build/win32 --target vanahub_package

deploy-local:
	./scripts/deploy-local.sh "$(DEPLOY_ROOT)"
