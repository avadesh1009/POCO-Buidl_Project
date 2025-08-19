cmake_minimum_required(VERSION 3.15)
project(my_ssl_app)
set(CMAKE_CXX_STANDARD 17)

# ========= Single Output Folder =========
set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
file(MAKE_DIRECTORY ${OUTPUT_DIR})

# ========= User-Defined Build Target =========
# Usage:
#   cmake -S . -B build -DTARGET_OS=windows
#   cmake -S . -B build -DTARGET_OS=mac
#   cmake -S . -B build -DTARGET_OS=linux
if(NOT TARGET_OS)
    message(FATAL_ERROR "Please specify -DTARGET_OS=windows|mac|linux")
endif()

# ========= Common =========
set(SRC_FILES 
    src/main.cpp
    src/Mx_Non_SecureSocket.cpp
    src/Mx_BaseSocket.cpp
    src/Mx_SecureSocket.cpp
)

# Update copy_runtime_libs to always copy to OUTPUT_DIR
function(copy_runtime_libs target lib_dir)
    if(EXISTS "${lib_dir}")
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${lib_dir}" "${OUTPUT_DIR}"
        )
    endif()
endfunction()

# Set the executable output folder for all platforms
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}")

# ========= Platform Selection =========
if(TARGET_OS STREQUAL "windows")
    set(POCO_ROOT      "${CMAKE_SOURCE_DIR}/thirdParty/window/Poco-1.14.2/install")
    set(OPENSSL_ROOT   "${CMAKE_SOURCE_DIR}/thirdParty/window/openssl-3.5.2/install")

    include_directories(
        ${POCO_ROOT}/include
        ${OPENSSL_ROOT}/include
    )
    link_directories(
        ${POCO_ROOT}/lib
        ${OPENSSL_ROOT}/lib/VC/x64/MD
    )

    add_executable(my_ssl_app ${SRC_FILES})
    target_link_libraries(my_ssl_app
        PocoCrypto
        PocoNet
        PocoFoundation
        libssl
        libcrypto
        ws2_32
    )

    copy_runtime_libs(my_ssl_app "${POCO_ROOT}/bin")

elseif(TARGET_OS STREQUAL "mac")
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/thirdParty/mac/openssl-3.5.2/install")
    find_package(OpenSSL REQUIRED)

    set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdParty/mac/Poco-1.14.2/install")
    find_package(Poco REQUIRED Foundation Net NetSSL Crypto Util)

    set(CMAKE_INSTALL_RPATH "@executable_path")
    set(CMAKE_BUILD_RPATH   "@executable_path")

    add_executable(my_ssl_app ${SRC_FILES})
    target_link_libraries(my_ssl_app
        PRIVATE Poco::Foundation Poco::Net Poco::NetSSL Poco::Crypto Poco::Util
                OpenSSL::SSL OpenSSL::Crypto
    )

    copy_runtime_libs(my_ssl_app "${CMAKE_SOURCE_DIR}/thirdParty/mac/Poco-1.14.2/install/lib")
    copy_runtime_libs(my_ssl_app "${CMAKE_SOURCE_DIR}/thirdParty/mac/openssl-3.5.2/install/lib")

elseif(TARGET_OS STREQUAL "linux")
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/thirdParty/linux/openssl-3.5.2/install")
    find_package(OpenSSL REQUIRED)

    set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdParty/linux/Poco-1.14.2/install")
    find_package(Poco REQUIRED Foundation Net NetSSL Crypto Util)

    set(CMAKE_INSTALL_RPATH "$ORIGIN")
    set(CMAKE_BUILD_RPATH   "$ORIGIN")

    add_executable(my_ssl_app ${SRC_FILES})
    target_link_libraries(my_ssl_app
        PRIVATE Poco::Foundation Poco::Net Poco::NetSSL Poco::Crypto Poco::Util
                OpenSSL::SSL OpenSSL::Crypto
    )

    copy_runtime_libs(my_ssl_app "${CMAKE_SOURCE_DIR}/thirdParty/linux/Poco-1.14.2/install/lib")
    copy_runtime_libs(my_ssl_app "${CMAKE_SOURCE_DIR}/thirdParty/linux/openssl-3.5.2/install/lib")

else()
    message(FATAL_ERROR "Unknown TARGET_OS: ${TARGET_OS}")
endif()
