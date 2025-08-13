#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Poco::ActiveRecord" for configuration "Release"
set_property(TARGET Poco::ActiveRecord APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Poco::ActiveRecord PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPocoActiveRecord.so.112"
  IMPORTED_SONAME_RELEASE "libPocoActiveRecord.so.112"
  )

list(APPEND _IMPORT_CHECK_TARGETS Poco::ActiveRecord )
list(APPEND _IMPORT_CHECK_FILES_FOR_Poco::ActiveRecord "${_IMPORT_PREFIX}/lib/libPocoActiveRecord.so.112" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
