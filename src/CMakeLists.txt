find_package(OpenSSL 1.1.0 REQUIRED)

add_executable(sscep sscep.c)

target_sources(sscep
        PRIVATE
            configuration.c
            engine.c
            fileutils.c
            fileutils_capi.c
            ias.c
            net.c
            pkcs7.c
            sceputils.c
            sscep.c
            log.c
	        cmd.c
        )

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(sscep
	PRIVATE
		${OPENSSL_LIBRARIES}
)

install(TARGETS sscep
	RUNTIME DESTINATION /usr/sbin
)

execute_process(COMMAND bash -c "cat /etc/os-release | grep -i UBUNTU_CODENAME | cut -d'=' -f2 | tr -d '\n'" OUTPUT_VARIABLE DISTRO)
execute_process(COMMAND dpkg --print-architecture COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
file (STRINGS "../VERSION" CPACK_PACKAGE_VERSION)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VERSION "0.8.0")
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dräger - GitHub")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "C implementation of the scep protocol.")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl")
set(CPACK_DEBIAN_FILE_NAME "${CMAKE_PROJECT_NAME}_${CPACK_PACKAGE_VERSION}-${DISTRO}_${ARCHITECTURE}.deb")
include(CPack)
