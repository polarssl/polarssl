add_executable(frontend frontend.c ../../library/net_sockets.c)
target_link_libraries(frontend)

install(TARGETS frontend
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

