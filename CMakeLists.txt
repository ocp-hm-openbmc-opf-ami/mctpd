cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

#Set project name here
project(mctpd CXX)

option(BUILD_STANDALONE "Use outside of YOCTO depedencies system" OFF)

set(BUILD_SHARED_LIBRARIES OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DMCTP_ASTPCIE_RESPONSE_WA)

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} \
    -Werror \
    -Wall \
    -Wextra \
    -Wshadow \
    -Wnon-virtual-dtor \
    -Wold-style-cast \
    -Wcast-align \
    -Wunused \
    -Woverloaded-virtual \
    -Wpedantic \
    -Wconversion \
    -Wnull-dereference \
    -Wdouble-promotion \
    -Wformat=2 \
")

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} \
        -Wuseless-cast \
        -Wduplicated-cond \
        -Wduplicated-branches \
        -Wlogical-op \
    ")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} \
        -Wno-c++20-designator \
        -Wno-c99-extensions \
        -Wno-gnu-zero-variadic-macro-arguments \
    ")
endif()

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -fno-rtti -I ${STAGING_KERNEL_DIR}/include/uapi
     -I ${STAGING_KERNEL_DIR}/include")

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

#Add header and sources here
set(SRC_FILES
    ${PROJECT_SOURCE_DIR}/src/main.cpp
    ${PROJECT_SOURCE_DIR}/src/MCTPBinding.cpp
    ${PROJECT_SOURCE_DIR}/src/SMBusBinding.cpp
    ${PROJECT_SOURCE_DIR}/src/PCIeBinding.cpp
    ${PROJECT_SOURCE_DIR}/src/I3CBinding.cpp
    ${PROJECT_SOURCE_DIR}/src/hw/DeviceMonitor.cpp
    ${PROJECT_SOURCE_DIR}/src/hw/PCIeDriver.cpp
    ${PROJECT_SOURCE_DIR}/src/hw/aspeed/PCIeMonitor.cpp
    ${PROJECT_SOURCE_DIR}/src/hw/aspeed/PCIeDriver.cpp
    ${PROJECT_SOURCE_DIR}/src/hw/aspeed/I3CDriver.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/Configuration.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/device_watcher.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/transmission_queue.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/eid_pool.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/smbus_utils.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/i3c_utils.cpp
    ${PROJECT_SOURCE_DIR}/src/utils/binding_utils.cpp
    ${PROJECT_SOURCE_DIR}/src/routing_table.cpp
    ${PROJECT_SOURCE_DIR}/src/service_scanner.cpp
    ${PROJECT_SOURCE_DIR}/src/mctp_dbus_interfaces.cpp
    ${PROJECT_SOURCE_DIR}/src/mctp_device.cpp
    ${PROJECT_SOURCE_DIR}/src/mctp_endpoint.cpp
    ${PROJECT_SOURCE_DIR}/src/mctp_bridge.cpp
    ${PROJECT_SOURCE_DIR}/src/smbus_device.cpp
    ${PROJECT_SOURCE_DIR}/src/smbus_endpoint.cpp
    ${PROJECT_SOURCE_DIR}/src/smbus_bridge.cpp
    )

set(HEADER_FILES
    ${PROJECT_SOURCE_DIR}/include/MCTPBinding.hpp
    ${PROJECT_SOURCE_DIR}/include/SMBusBinding.hpp
    ${PROJECT_SOURCE_DIR}/include/PCIeBinding.hpp
    ${PROJECT_SOURCE_DIR}/include/mctp_dbus_interfaces.hpp
    ${PROJECT_SOURCE_DIR}/include/mctp_device.hpp
    ${PROJECT_SOURCE_DIR}/include/mctp_cmd_encoder.hpp
    ${PROJECT_SOURCE_DIR}/include/mctp_endpoint.hpp
    ${PROJECT_SOURCE_DIR}/include/mctp_bridge.hpp
    ${PROJECT_SOURCE_DIR}/include/smbus_device.hpp
    ${PROJECT_SOURCE_DIR}/include/smbus_endpoint.hpp
    ${PROJECT_SOURCE_DIR}/include/smbus_bridge.hpp
    ${PROJECT_SOURCE_DIR}/include/I3CBinding.hpp)


include_directories(${PROJECT_SOURCE_DIR}/include)

set(SERVICE_FILES
    ${PROJECT_SOURCE_DIR}/service_files/xyz.openbmc_project.mctpd@.service)

if(BUILD_STANDALONE)
  set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/libs/googletest/
                        ${CMAKE_BINARY_DIR}/libs/boost/ ${CMAKE_PREFIX_PATH})

  configure_file(CMakeLists.txt.in 3rdparty/CMakeLists.txt)
  execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)
  execute_process(COMMAND ${
    CMAKE_COMMAND} --build .
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/3rdparty)

  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/sdbusplus/include)
  link_directories(${CMAKE_BINARY_DIR}/libs/sdbusplus/lib)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/src/phosphor-logging/lib/include)
  link_directories(${CMAKE_BINARY_DIR}/src/phosphor-logging/.libs)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/libmctp/include)
  link_directories(${CMAKE_BINARY_DIR}/libs/libmctp/lib)
  include_directories(SYSTEM
                      ${CMAKE_BINARY_DIR}/libs/phosphor-dbus-interfaces/include)
  link_directories(${CMAKE_BINARY_DIR}/libs/phosphor-dbus-interfaces/lib)
  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/include)
  link_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/boost/lib)

  include_directories(SYSTEM ${CMAKE_BINARY_DIR}/libs/CLIUtils/include)
endif()

find_package(Boost 1.71 REQUIRED)
include_directories(SYSTEM ${BOOST_SRC_DIR})

add_executable(${PROJECT_NAME} ${SRC_FILES} ${HEADER_FILES})
target_link_libraries(
  ${PROJECT_NAME}
  sdbusplus
  systemd
  pthread
  phosphor_dbus
  mctp_intel
  udev
  i2c
  boost_coroutine)

find_package (PkgConfig REQUIRED)
pkg_get_variable(SYSTEMD_SYSTEM_UNIT_DIR systemd systemdsystemunitdir)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES ${SERVICE_FILES} DESTINATION "${SYSTEMD_SYSTEM_UNIT_DIR}")
install(FILES ${CONFIG_FILES} DESTINATION /usr/share/mctp/)

if(${MCTPD_BUILD_UT})
  include(CTest)

  set(SRC
      src/PCIeBinding.cpp src/SMBusBinding.cpp src/MCTPBinding.cpp
      src/hw/DeviceMonitor.cpp src/hw/PCIeDriver.cpp
      src/utils/Configuration.cpp src/utils/device_watcher.cpp
      src/utils/transmission_queue.cpp src/utils/eid_pool.cpp)

  set(TEST_FILES
      tests/test-mctpd.cpp tests/test-binding.cpp
      tests/test-pcie_binding-devices.cpp tests/test-pcie_binding-discovery.cpp)

  enable_testing()

  add_executable(test-mctpd ${SRC} ${TEST_FILES})
  target_compile_definitions(test-mctpd PRIVATE "USE_MOCK")
  include_directories(${PROJECT_SOURCE_DIR}/tests)

  find_package(GTest REQUIRED CONFIG)
  target_link_libraries(
    test-mctpd
    GTest::gtest_main
    GTest::gmock
    sdbusplus
    mctp_intel
    systemd
    pthread
    phosphor_dbus
    i2c
    boost_coroutine)

  add_test(test-mctpd test-mctpd "--gtest_output=xml:test-mctpd.xml")
  install(TARGETS test-mctpd DESTINATION bin)
endif(${MCTPD_BUILD_UT})
