# Copyright 2018, alex at staticlibs.net
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required ( VERSION 2.8.12 )

# project
project ( wilton_mozjs CXX )

# dependencies
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_icu )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_mozjs )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_utf8cpp )
set ( ${PROJECT_NAME}_DEPS
        staticlib_config
        staticlib_support
        staticlib_io
        staticlib_utils
        staticlib_json
        staticlib_pimpl
        utf8cpp
        mozjs )

staticlib_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# library
add_library ( ${PROJECT_NAME} SHARED
        ${CMAKE_CURRENT_LIST_DIR}/src/mozjs_engine.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/wiltoncall_mozjs.cpp )

target_link_libraries ( ${PROJECT_NAME} PRIVATE
        wilton_core
        wilton_loader
        wilton_logging
        ${${PROJECT_NAME}_DEPS_PC_LIBRARIES} )

target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/src
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${WILTON_DIR}/core/include
        ${WILTON_DIR}/modules/wilton_loader/include
        ${WILTON_DIR}/modules/wilton_logging/include
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )
        
target_compile_options ( ${PROJECT_NAME} PRIVATE 
        ${${PROJECT_NAME}_DEPS_PC_CFLAGS_OTHER}
        -Wno-unused-parameter
        -Wno-missing-field-initializers )
if ( CMAKE_BUILD_TYPE MATCHES "Release" AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 6.0 ))
    target_compile_options ( ${PROJECT_NAME} PRIVATE 
            # gcc 4.7 miscompiles this_thread::get_id()
            # stringification for some reason
            -O1 )
endif ( )

# debuginfo
staticlib_extract_debuginfo_shared ( ${PROJECT_NAME} )

# pkg-config
set ( ${PROJECT_NAME}_PC_CFLAGS "-I${CMAKE_CURRENT_LIST_DIR}/include" )
set ( ${PROJECT_NAME}_PC_LIBS "-L${CMAKE_LIBRARY_OUTPUT_DIRECTORY} -l${PROJECT_NAME}" )
staticlib_list_to_string ( ${PROJECT_NAME}_PC_REQUIRES_PRIVATE "" ${PROJECT_NAME}_DEPS )
configure_file ( ${WILTON_DIR}/resources/buildres/pkg-config.in 
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/pkgconfig/${PROJECT_NAME}.pc )
