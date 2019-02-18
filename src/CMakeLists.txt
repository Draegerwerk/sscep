#find_library(OpenSSL 1.1.0 REQUIRED)

find_library(OPENSSL_LIBRARIES NAMES crypto ssl PATHS /usr/local/ssl/lib)
find_path(OPENSSL_INCLUDE_DIR asn1.h PATHS /usr/local/ssl/include)
#include_directories(/usr/local/ssl/)

set(OPENSSL_INCLUDE_DIR /usr/local/ssl/include)
set(OPENSSL_LIBRARIES crypto ssl)

#add_library(ssl SHARED IMPORTED) # or STATIC instead of SHARED
#add_library(crypto SHARED IMPORTED)
#set_target_properties(bar PROPERTIES
#  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/libbar.so"
#  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/include/libbar"
#)

add_executable(sscep sscep.c)

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
            getopt.h
            getopt.c
            ias.h
            ias.c
            net.c
            pkcs7.c
            sceputils.c
            sscep.c
            sscep.h
        )

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(sscep
	PRIVATE
		${OPENSSL_LIBRARIES}
)

