cmake_minimum_required(VERSION 3.15)
project(my_ssl_app)

set(CMAKE_CXX_STANDARD 17)

if(WIN32)
    # ======== Windows Paths ========
    set(POCO_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/thirdParty/window/Poco-1.14.2/install/include")
    set(POCO_LIB_DIR     "${CMAKE_SOURCE_DIR}/thirdParty/window/Poco-1.14.2/install/lib")

    set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/thirdParty/window/openssl-3.5.2/install/include")
    set(OPENSSL_LIB_DIR     "${CMAKE_SOURCE_DIR}/thirdParty/window/openssl-3.5.2/install/lib/VC/x64/MD")

    include_directories(${POCO_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})
    link_directories(${POCO_LIB_DIR} ${OPENSSL_LIB_DIR})

    add_executable(my_ssl_app src/main.cpp)

    # Link by name only — Windows loader will look in exe folder first
    target_link_libraries(my_ssl_app
        PocoCrypto
        PocoNet
        PocoFoundation
        libssl
        libcrypto
        ws2_32
    )

    # Post-build: copy DLLs to the same folder as the executable
    add_custom_command(TARGET my_ssl_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${POCO_LIB_DIR}" "$<TARGET_FILE_DIR:my_ssl_app>"
    )
    add_custom_command(TARGET my_ssl_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${OPENSSL_LIB_DIR}" "$<TARGET_FILE_DIR:my_ssl_app>"
    )

else() # Linux / Unix
    # ======== RPATH SETTINGS ========
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)   # Don't add absolute paths automatically
    set(CMAKE_INSTALL_RPATH "$ORIGIN")             # Only relative to executable
    set(CMAKE_BUILD_RPATH "$ORIGIN")               # Only relative to executable

    # ======== FIND OPENSSL ========
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/thirdParty/linux/openssl-3.5.2/install")
    find_package(OpenSSL REQUIRED)

    # ======== FIND POCO ========
    set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdParty/linux/Poco-1.14.2/install")
    find_package(Poco REQUIRED Foundation Net NetSSL Crypto Util)

    # ======== SOURCE FILES ========
    add_executable(my_ssl_app src/main.cpp)

    # ======== LINK LIBRARIES ========
    target_link_libraries(my_ssl_app
        PRIVATE
            Poco::Foundation
            Poco::Net
            Poco::NetSSL
            Poco::Crypto
            Poco::Util
            OpenSSL::SSL
            OpenSSL::Crypto
    )

    # Post-build: copy .so files to the same directory as executable
    add_custom_command(TARGET my_ssl_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/thirdParty/linux/Poco-1.14.2/install/lib" "$<TARGET_FILE_DIR:my_ssl_app>"
    )
    add_custom_command(TARGET my_ssl_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/thirdParty/linux/openssl-3.5.2/install/lib" "$<TARGET_FILE_DIR:my_ssl_app>"
    )

endif()

