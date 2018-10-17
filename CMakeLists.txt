cmake_minimum_required(VERSION 3.5)

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

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
target_link_libraries(sscep
        PRIVATE
            ssl
            crypto
            dl)