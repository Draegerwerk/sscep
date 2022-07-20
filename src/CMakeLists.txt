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

file (STRINGS "../VERSION" CPACK_PACKAGE_VERSION)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optinal")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Dräger - GitHub")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "SSCEP is a command line client for the SCEP protocol")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl")
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
include(CPack)
