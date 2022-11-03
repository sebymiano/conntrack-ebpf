# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(src)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tools/cmake)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NL3 REQUIRED libnl-3.0)
# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    ARCH= 
    CROSS_COMPILE=
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
    -C ${CMAKE_CURRENT_SOURCE_DIR}/../bpftool/src bootstrap
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(libargparse
  PREFIX libargparse
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../libargparse
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    -C ${CMAKE_CURRENT_SOURCE_DIR}/../libargparse && 
    cp ${CMAKE_CURRENT_SOURCE_DIR}/../libargparse/libargparse.a 
    ${CMAKE_CURRENT_BINARY_DIR}/libargparse
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(liblog
  PREFIX liblog
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../liblog
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMAKE_C_COMPILER} 
    -DLOG_USE_COLOR
    -c ${CMAKE_CURRENT_SOURCE_DIR}/../liblog/src/log.c 
    -o ${CMAKE_CURRENT_BINARY_DIR}/liblog.o
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
set(LIBARGPARSE_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../libargparse)
set(LIBARGPARSE_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libargparse/libargparse.a)
set(LIBLOG_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../liblog/src)
set(LIBLOG_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/liblog.o)

find_package(BpfObject REQUIRED)

# Create an executable for each application
file(GLOB apps *.bpf.c)
foreach(app ${apps})
  get_filename_component(app_stem ${app} NAME_WE)
  # include_directories(${LIBARGPARSE_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS})
  # Build object skeleton and depend skeleton on libbpf build
  bpf_object(${app_stem} ${app_stem}.bpf.c)
  add_dependencies(${app_stem}_skel libbpf-build bpftool-build libargparse-build liblog-build)

  add_executable(${app_stem} ${app_stem}.c)
  target_include_directories(${app_stem} PRIVATE ${LIBARGPARSE_INCLUDE_DIRS} ${LIBLOG_INCLUDE_DIRS} ${NL3_INCLUDE_DIRS})
  target_link_libraries(${app_stem} ${app_stem}_skel ${LIBARGPARSE_LIBRARIES} ${LIBLOG_LIBRARIES} ${NL3_LIBRARIES})
endforeach()
