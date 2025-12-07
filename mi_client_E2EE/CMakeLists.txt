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

option(MI_BUILD_QT_CLIENT "Build Qt GUI client" OFF)
if(MI_BUILD_QT_CLIENT)
    find_package(Qt6 COMPONENTS Widgets Network Concurrent REQUIRED)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC OFF)
    set(QT_UI_ASSETS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/qt_ui/main.qss
    )
    add_executable(mi_qt_client
        src/qt_ui/main.cpp
        src/qt_ui/BackendService.cpp
        src/qt_ui/ChatWidget.cpp
        src/qt_ui/ConversationItemWidget.cpp
        src/qt_ui/LoginWindow.cpp
        src/qt_ui/MainWindow.cpp
        src/qt_ui/MessageDelegate.cpp
        src/qt_ui/MessageModel.cpp
        src/qt_ui/MessageReceiverThread.cpp
        ${QT_UI_ASSETS}
    )
    target_include_directories(mi_qt_client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/qt_ui
        ${PROJECT_SOURCE_DIR}/include
    )
    target_link_libraries(mi_qt_client PRIVATE
        mi_client_e2ee
        Qt6::Widgets
        Qt6::Network
        Qt6::Concurrent
    )
    target_compile_features(mi_qt_client PRIVATE cxx_std_17)
    foreach(asset IN LISTS QT_UI_ASSETS)
        add_custom_command(TARGET mi_qt_client POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${asset}" "$<TARGET_FILE_DIR:mi_qt_client>/"
        )
    endforeach()
    if(WIN32)
        # 可选：查找 windeployqt 用于收集运行时依赖
        find_program(WINDEPLOYQT_EXECUTABLE windeployqt)
        if(WINDEPLOYQT_EXECUTABLE)
            add_custom_command(TARGET mi_qt_client POST_BUILD
                COMMAND "${WINDEPLOYQT_EXECUTABLE}" "$<TARGET_FILE:mi_qt_client>"
                COMMENT "Running windeployqt for mi_qt_client"
            )
        endif()
    endif()
endif()
