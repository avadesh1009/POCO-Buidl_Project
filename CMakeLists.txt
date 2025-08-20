cmake_minimum_required(VERSION 3.16)
project(CommonSDK)

# ------------------------------
# Ensure TARGET_OS is specified
# ------------------------------
if(NOT TARGET_OS)
    message(FATAL_ERROR "Please specify -DTARGET_OS=windows|mac|linux")
endif()

# ------------------------------
# Print compiler and set C++20
# ------------------------------
message(STATUS "Using compiler: ${CMAKE_CXX_COMPILER}")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ------------------------------
# Single output folder
# ------------------------------
set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
file(MAKE_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIR}")

# ------------------------------
# Include project headers
# ------------------------------
include_directories(
    ../src
    ../src/utils
)

# ------------------------------
# Platform-specific configuration
# ------------------------------
set(RUNTIME_LIB_DIRS "")
set(LINK_LIBS "")

if(TARGET_OS STREQUAL "windows")
    set(POCO_ROOT    "${CMAKE_SOURCE_DIR}/thirdParty/window/Poco-1.14.2/install")
    set(OPENSSL_ROOT "${CMAKE_SOURCE_DIR}/thirdParty/window/openssl-3.5.2/install")

    include_directories(${POCO_ROOT}/include ${OPENSSL_ROOT}/include)
    link_directories(${POCO_ROOT}/lib ${OPENSSL_ROOT}/lib/VC/x64/MD)

    set(LINK_LIBS
        PocoCrypto
        PocoNet
        PocoFoundation
        libssl
        libcrypto
        ws2_32
        gtest
        gtest_main
    )

    list(APPEND RUNTIME_LIB_DIRS
        ${POCO_ROOT}/bin
    )

elseif(TARGET_OS STREQUAL "mac" OR TARGET_OS STREQUAL "linux")
    if(TARGET_OS STREQUAL "mac")
        set(PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdParty/mac")
        set(RPATH "@executable_path")
    else()
        set(PREFIX_PATH "${CMAKE_SOURCE_DIR}/thirdParty/linux")
        set(RPATH "$ORIGIN")
    endif()

    set(OPENSSL_ROOT_DIR "${PREFIX_PATH}/openssl-3.5.2/install")
    find_package(OpenSSL REQUIRED)

    set(CMAKE_PREFIX_PATH "${PREFIX_PATH}/Poco-1.14.2/install")
    find_package(Poco REQUIRED Foundation Net NetSSL Crypto Util)

    set(CMAKE_INSTALL_RPATH "${RPATH}")
    set(CMAKE_BUILD_RPATH   "${RPATH}")

    set(LINK_LIBS
        Poco::Foundation Poco::Net Poco::NetSSL Poco::Crypto Poco::Util
        OpenSSL::SSL OpenSSL::Crypto GTest::gtest GTest::gtest_main
    )

    list(APPEND RUNTIME_LIB_DIRS
        "${PREFIX_PATH}/Poco-1.14.2/install/lib"
        "${PREFIX_PATH}/openssl-3.5.2/install/lib"
    )

else()
    message(FATAL_ERROR "Unknown TARGET_OS: ${TARGET_OS}")
endif()

# ------------------------------
# Generic helper function to create executables
# ------------------------------
# exe_name       - name of the executable
# source_files   - list of source files (semicolon-separated)
# link_libs      - libraries to link (optional)
# runtime_dirs   - runtime library directories to copy (optional)
# is_test        - TRUE/FALSE if this is a gtest (optional)
# ------------------------------
function(add_executable_common exe_name source_files link_libs runtime_dirs is_test)
    add_executable(${exe_name} ${source_files})

    if(link_libs)
        target_link_libraries(${exe_name} PRIVATE ${link_libs})
    endif()

    if(runtime_dirs)
        foreach(dir ${runtime_dirs})
            if(EXISTS "${dir}")
                add_custom_command(TARGET ${exe_name} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_directory
                    "${dir}" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
                )
            endif()
        endforeach()
    endif()

    if(is_test)
        add_test(NAME ${exe_name} COMMAND ${exe_name})
    endif()
endfunction()

# ------------------------------
# Enable testing and add GoogleTest
# ------------------------------
enable_testing()
add_subdirectory(googletest googletest-build)

# ------------------------------
# Build main executable
# ------------------------------
set(MAIN_SRC_FILES
    ../src/main.cpp
    ../src/Mx_Non_SecureSocket.cpp
    ../src/Mx_BaseSocket.cpp
    ../src/Mx_SecureSocket.cpp
)
add_executable_common(Socket_test
    "${MAIN_SRC_FILES}" "${LINK_LIBS}" "${RUNTIME_LIB_DIRS}" FALSE)

