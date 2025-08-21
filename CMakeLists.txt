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
    set(POCO_ROOT    "${CMAKE_SOURCE_DIR}/../thirdParty/window/Poco-1.14.2/install")
    set(OPENSSL_ROOT "${CMAKE_SOURCE_DIR}/../thirdParty/window/openssl-3.5.2/install")

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

    # Poco libraries for runtime copy
    set(POCO_LIB_NAMES
        PocoCrypto
        PocoFoundation
        PocoJSON
        PocoNet
        PocoNetSSL
        PocoUtil
        PocoXML
    )

    set(POCO_LIB_EXT ".dll")
    foreach(lib ${POCO_LIB_NAMES})
        list(APPEND RUNTIME_LIB_DIRS "${POCO_ROOT}/bin/${lib}${POCO_LIB_EXT}")
    endforeach()

elseif(TARGET_OS STREQUAL "mac" OR TARGET_OS STREQUAL "linux")
    if(TARGET_OS STREQUAL "mac")
        set(PREFIX_PATH "${CMAKE_SOURCE_DIR}/../thirdParty/mac")
        set(RPATH "@executable_path")
        set(POCO_LIB_EXT ".112.dylib")
    else()
        set(PREFIX_PATH "${CMAKE_SOURCE_DIR}/../thirdParty/linux")
        set(RPATH "$ORIGIN")
        set(POCO_LIB_EXT ".so.112")
    endif()

    # OpenSSL
    set(OPENSSL_ROOT_DIR "${PREFIX_PATH}/openssl-3.5.2/install")
    find_package(OpenSSL REQUIRED)

    # Poco
    set(CMAKE_PREFIX_PATH "${PREFIX_PATH}/Poco-1.14.2/install")
    find_package(Poco REQUIRED Foundation Net NetSSL Crypto Util)

    # RPATH
    set(CMAKE_INSTALL_RPATH "${RPATH}")
    set(CMAKE_BUILD_RPATH   "${RPATH}")

    set(LINK_LIBS
        Poco::Foundation Poco::Net Poco::NetSSL Poco::Crypto Poco::Util
        OpenSSL::SSL OpenSSL::Crypto GTest::gtest GTest::gtest_main
    )

    # Poco libraries for runtime copy
    set(POCO_LIB_NAMES
        PocoCrypto
        PocoFoundation
        PocoJSON
        PocoNet
        PocoNetSSL
        PocoUtil
        PocoXML
    )

    foreach(lib ${POCO_LIB_NAMES})
        list(APPEND RUNTIME_LIB_DIRS "${PREFIX_PATH}/Poco-1.14.2/install/lib/lib${lib}${POCO_LIB_EXT}")
    endforeach()

else()
    message(FATAL_ERROR "Unknown TARGET_OS: ${TARGET_OS}")
endif()


# ------------------------------
# Generic helper function to create executables
# ------------------------------
# exe_name       - Name of the executable to create
# source_files   - List of source files (semicolon-separated)
# link_libs      - Libraries to link (optional)
# files_to_copy  - List of specific files to copy to runtime output dir (optional)
#                  Each file will be copied as-is (no renaming)
# is_test        - TRUE/FALSE if this executable should be added as a CTest test (optional)
# ------------------------------
function(add_executable_common exe_name source_files link_libs files_to_copy is_test)

    # Create the executable
    add_executable(${exe_name} ${source_files})

    # Link optional libraries
    if(link_libs)
        target_link_libraries(${exe_name} PRIVATE ${link_libs})
    endif()

    # Copy specific files to the runtime output directory
    if(files_to_copy)
        foreach(file ${files_to_copy})
            if(EXISTS "${file}")
                add_custom_command(TARGET ${exe_name} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy
                    "${file}" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
                )
            endif()
        endforeach()
    endif()

    # Register as a test if requested
    if(is_test)
        add_test(NAME ${exe_name} COMMAND ${exe_name})
    endif()

endfunction()

# ------------------------------
# Build main executable
# ------------------------------
set(MAIN_SRC_FILES
    Socket_test.cpp
    ../src/utils/Mx_Non_SecureSocket.cpp
    ../src/utils/Mx_BaseSocket.cpp
    ../src/utils/Mx_SecureSocket.cpp
)
add_executable_common(Socket_test
    "${MAIN_SRC_FILES}" "${LINK_LIBS}" "${RUNTIME_LIB_DIRS}" FALSE)

# ------------------------------
# Enable testing and add GoogleTest
# ------------------------------
enable_testing()
add_subdirectory(../googletest googletest-build)

# ------------------------------
# Register tests using the common helper
# ------------------------------
add_executable_common(RandomStringGenerator_test
    "../src/utils/Mx_RandomStringGenerator.cpp;Mx_RandomStringGenerator_test.cpp"
    "gtest;gtest_main"
    ""
    TRUE
)

add_executable_common(Mx_Queue_Map_test
    "Mx_Map_test.cpp;Mx_Queue_test.cpp"
    "gtest;gtest_main"
    ""
    TRUE
)

add_executable_common(Mx_CommandParser_Test
    "Mx_CommandParser_Test.cpp"
    "gtest;gtest_main"
    ""
    TRUE
)

add_executable_common(Mx_ConfigParser_Test
    "Mx_ConfigParser_Test.cpp"
    "gtest;gtest_main"
    ""
    TRUE
)
