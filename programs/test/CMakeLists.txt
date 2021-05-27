set(libs
    ${mbedtls_target}
)

set(executables_libs
    selftest
    udp_proxy
)

set(executables_mbedcrypto
    benchmark
    query_compile_time_config
    zeroize
)

if(TEST_CPP)
    list(APPEND executables_mbedcrypto cpp_dummy_build)
endif()

find_package(Perl REQUIRED)

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/query_config.c
    COMMAND
        ${PERL}
            ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/generate_query_config.pl
            ${CMAKE_CURRENT_SOURCE_DIR}/../../include/mbedtls/config.h
            ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/data_files/query_config.fmt
            ${CMAKE_CURRENT_BINARY_DIR}/query_config.c
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/generate_query_config.pl
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include/mbedtls/config.h
        ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/data_files/query_config.fmt
)
# this file will also be used in anoter directory, so create a target, see
# https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#how-can-i-add-a-dependency-to-a-source-file-which-is-generated-in-a-subdirectory
add_custom_target(generate_query_config_c
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/query_config.c)

foreach(exe IN LISTS executables_libs executables_mbedcrypto)
    set(extra_sources "")
    if(exe STREQUAL "query_compile_time_config")
        list(APPEND extra_sources
            ${CMAKE_CURRENT_SOURCE_DIR}/query_config.h
            ${CMAKE_CURRENT_BINARY_DIR}/query_config.c)
    endif()
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>
        ${extra_sources})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/include)
    if(exe STREQUAL "query_compile_time_config")
        target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    # This emulates "if ( ... IN_LIST ... )" which becomes available in CMake 3.3
    list(FIND executables_libs ${exe} exe_index)
    if (${exe_index} GREATER -1)
        target_link_libraries(${exe} ${libs})
    else()
        target_link_libraries(${exe} ${mbedcrypto_target})
    endif()
endforeach()

install(TARGETS ${executables_libs} ${executables_mbedcrypto}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
