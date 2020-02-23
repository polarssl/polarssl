set(libs
    mbedtls
)

add_executable(strerror strerror.c)
target_link_libraries(strerror ${libs})

add_executable(rfc_3526_7919_verify rfc_3526_7919_verify.c)
target_link_libraries(rfc_3526_7919_verify mbedtls)

add_executable(pem2der pem2der.c)
target_link_libraries(pem2der ${libs})

install(TARGETS strerror pem2der
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
