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
install (TARGETS sscep RUNTIME DESTINATION bin)
