#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Poco::Prometheus" for configuration "Release"
set_property(TARGET Poco::Prometheus APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Poco::Prometheus PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libPocoPrometheus.so.112"
  IMPORTED_SONAME_RELEASE "libPocoPrometheus.so.112"
  )

list(APPEND _IMPORT_CHECK_TARGETS Poco::Prometheus )
list(APPEND _IMPORT_CHECK_FILES_FOR_Poco::Prometheus "${_IMPORT_PREFIX}/lib/libPocoPrometheus.so.112" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
