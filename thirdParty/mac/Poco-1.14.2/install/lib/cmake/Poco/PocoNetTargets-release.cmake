#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Poco::Net" for configuration "Release"
set_property(TARGET Poco::Net APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Poco::Net PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPocoNet.112.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libPocoNet.112.dylib"
  )

list(APPEND _cmake_import_check_targets Poco::Net )
list(APPEND _cmake_import_check_files_for_Poco::Net "${_IMPORT_PREFIX}/lib/libPocoNet.112.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
