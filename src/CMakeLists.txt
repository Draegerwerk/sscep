find_package(OpenSSL 1.1.0 REQUIRED)

add_executable(sscep "")

target_sources(sscep
        PRIVATE
            conf.h
            cmd.h
            configuration.h
            configuration.c
            engine.c
            engine.h
            fileutils.c
            fileutils_capi.h
            fileutils_capi.c
            ias.h
            ias.c
            net.c
            pkcs7.c
            sceputils.c
            sscep.c
            sscep.h
        )

target_link_libraries(sscep
	PRIVATE
		${OPENSSL_LIBRARIES}
)
install (TARGETS sscep RUNTIME DESTINATION bin)
