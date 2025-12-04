add_library(mi_client_e2ee STATIC
    src/mi_client_api.cpp
    src/kcp_transport.cpp
    src/file_chunker.cpp
    src/encrypted_types.cpp
)

target_include_directories(mi_client_e2ee
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(mi_client_e2ee PUBLIC mi_common mi_internal)
if(MI_USE_KCP)
    if(KCP_INCLUDE_DIR)
        target_include_directories(mi_client_e2ee PRIVATE ${KCP_INCLUDE_DIR})
    endif()
    if(KCP_LIBRARY)
        target_link_libraries(mi_client_e2ee PRIVATE ${KCP_LIBRARY})
    endif()
    if(WIN32)
        target_link_libraries(mi_client_e2ee PRIVATE ws2_32)
    endif()
endif()
target_compile_definitions(mi_client_e2ee PRIVATE MI_BUILD)
