add_executable(pbcrypt pbcrypt.c)
target_link_libraries(pbcrypt mbedtls)

install(TARGETS pbcrypt
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
