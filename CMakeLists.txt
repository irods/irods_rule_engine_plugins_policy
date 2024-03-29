cmake_minimum_required(VERSION 3.5.0 FATAL_ERROR) #CPACK_DEBIAN_<COMPONENT>_PACKAGE_NAME


find_package(IRODS 4.3.0 EXACT REQUIRED)
set(IRODS_PLUGIN_REVISION "0")

set(CMAKE_C_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")

set(PROJECT_NAME irods_rule_engine_plugin)
string(REPLACE "_" "-" PROJECT_NAME_HYPHENS ${PROJECT_NAME})

project( ${PROJECT_NAME} C CXX)
include(${IRODS_TARGETS_PATH})

set(IRODS_PLUGIN_VERSION "${IRODS_VERSION}.${IRODS_PLUGIN_REVISION}")

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if (NOT CPACK_PACKAGING_INSTALL_PREFIX)
  set(CPACK_PACKAGING_INSTALL_PREFIX "/" CACHE STRING "Package root path. \"/\" is correct for normal package builds.." FORCE)
  message(STATUS "Setting unspecified CPACK_PACKAGING_INSTALL_PREFIX to '${CPACK_PACKAGING_INSTALL_PREFIX}'. This is the correct setting for normal builds.")
endif()


if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
  message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'")
endif()

if (NOT IRODS_EXTERNALS_PACKAGE_ROOT)
  set(IRODS_EXTERNALS_PACKAGE_ROOT "/opt/irods-externals" CACHE STRING "Choose the location of iRODS external packages." FORCE)
  message(STATUS "Setting unspecified IRODS_EXTERNALS_PACKAGE_ROOT to '${IRODS_EXTERNALS_PACKAGE_ROOT}'")
endif()

macro(IRODS_MACRO_SET_AND_CHECK_DEPENDENCY_FULL_PATH DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  if (NOT IS_DIRECTORY ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
    message(FATAL_ERROR "${DEPENDENCY_NAME} not found at ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY}")
  endif()
  set(IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME} ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
endmacro()

set(CMAKE_C_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(nlohmann_json "3.6.1" REQUIRED)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -stdlib=libc++")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -stdlib=libc++")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,-z,defs")
add_compile_options(-nostdinc++)
add_compile_options(-std=c++17)
link_libraries(c++abi)
include_directories(
    ${IRODS_EXTERNALS_FULLPATH_CLANG}/include/c++/v1
    )

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_CONTACT "Renaissance Computing Institute <info@irods.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")
set(CPACK_PACKAGE_VENDOR "Renaissance Computing Institute <info@irods.org>")

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_SECTION "contrib/science")
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://irods.org")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_VENDOR "iRODS Consortium")
set(CPACK_RPM_PACKAGE_URL "https://irods.org")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)

include(/usr/lib/irods/cmake/policy_composition_framework_cmake_utilities.cmake)

# CPACK names component package files as "${CPACK_PACKAGE_FILE_NAME}-${COMPONENT_NAME}"
# CPackDeb TO_UPPERs all the component names when checking the ${CPACK_DEBIAN_<COMPONENT>...} variables

# include all cmake files for rule engine plugins for this repository

include(${CMAKE_SOURCE_DIR}/access_time.cmake)
include(${CMAKE_SOURCE_DIR}/data_replication.cmake)
include(${CMAKE_SOURCE_DIR}/data_retention.cmake)
include(${CMAKE_SOURCE_DIR}/data_verification.cmake)
include(${CMAKE_SOURCE_DIR}/filesystem_usage.cmake)
include(${CMAKE_SOURCE_DIR}/log_context.cmake)
include(${CMAKE_SOURCE_DIR}/query_processor.cmake)
include(${CMAKE_SOURCE_DIR}/testing_policy.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_data_object_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_metadata_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_collection_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_user_modified.cmake)
include(${CMAKE_SOURCE_DIR}/event_handler_resource_modified.cmake)
include(${CMAKE_SOURCE_DIR}/verify_checksum.cmake)

include(CPack)
