add_library(mi_server STATIC
    src/mi_server_api.cpp
    src/mysql_stub.cpp
    src/kcp_stub.cpp
)

target_include_directories(mi_server
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(mi_server PUBLIC mi_common mi_internal)
if(MI_USE_KCP AND KCP_LIBRARY)
    target_link_libraries(mi_server PUBLIC ${KCP_LIBRARY})
    target_include_directories(mi_server PRIVATE ${KCP_INCLUDE_DIR})
endif()
target_compile_definitions(mi_server PRIVATE MI_BUILD)

add_executable(mi_server_app
    src/server_main.cpp
)
target_link_libraries(mi_server_app PRIVATE mi_server)
