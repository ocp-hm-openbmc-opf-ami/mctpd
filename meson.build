project(
    'mctpd', ['c','cpp'],
    license: 'Apache-2.0',
    version: '0.1',
    meson_version: '>=1.1.1',
    default_options: [
        'warning_level=3',
        'werror=true',
        'cpp_std=c++23',
        'c_std=gnu11',
    ],
)

cmake = import('cmake')

# Supress Zero-size array error from libmctp
add_project_arguments(
    '-Wno-pedantic',
    '-DBOOST_DISABLE_ASSERTS',
    '-DBOOST_ASIO_NO_DEPRECATED',
    language: 'cpp',
)

yocto_build = get_option('yocto_dep')
build_tests = get_option('tests')

dep_required = false
if yocto_build.enabled()
    dep_required = true
endif

incdir = include_directories('include')

boost = dependency('boost', required: dep_required, version : '>=1.79.0',
        modules: [ 'coroutine', 'context'], include_type: 'system')
if not boost.found()
    boost_proj = subproject('boost')
    boost = boost_proj.get_variable('boost_dep')
endif

systemd = dependency('systemd', required: dep_required)
systemd_system_unit_dir = systemd.get_pkgconfig_variable(
    'systemdsystemunitdir',
    define_variable: ['prefix', get_option('prefix')])

cpp = meson.get_compiler('cpp')
if cpp.has_header('nlohmann/json.hpp')
    nlohmann_json_dep = declare_dependency()
    message('nlohmann json already found')
else
    nlohmann_json_dep = dependency('nlohmann-json', required: dep_required)
    subproject('nlohmann-json')
    nlohmann_json_dep = declare_dependency(
      include_directories: [
          'subprojects/nlohmann-json/single_include',
          'subprojects/nlohmann-json/single_include/nlohmann'])
endif

sdbusplus = dependency('sdbusplus', required : dep_required)
if not sdbusplus.found()
    sdbusplus_proj = subproject('sdbusplus')
    sdbusplus = sdbusplus_proj.get_variable('sdbusplus_dep')
endif

if not yocto_build.enabled() and build_tests.enabled()
    opt_var = cmake.subproject_options()
    opt_var.append_compile_args('c', '-Wno-pedantic')
    libmctp_proj = cmake.subproject('libmctp', options: opt_var)
    libmctp_dep = libmctp_proj.dependency('mctp_intel')

    phosphor_dbus_interfaces_proj = subproject('phosphor-dbus-interfaces')
    phosphor_dbus_interfaces_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_dbus_interfaces_dep')

    phosphor_dbus_interfaces_proj = subproject('phosphor-logging')
    phosphor_logging_dep = phosphor_dbus_interfaces_proj.get_variable('phosphor_logging_dep')
else
    libmctp_dep = meson.get_compiler('cpp').find_library('mctp_intel', required : dep_required)
    if not libmctp_dep.found()
        opt_var = cmake.subproject_options()
        opt_var.append_compile_args('c', '-Wno-pedantic')
        libmctp_proj = cmake.subproject('libmctp', options: opt_var)
        libmctp_dep = libmctp_proj.dependency('mctp_intel')
    endif

    phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces', required : true)
    phosphor_logging_dep = dependency('phosphor-logging', required : true)
endif

CLI11_dep = dependency('CLI11', required : dep_required)
if not CLI11_dep.found()
    CLI11_proj = subproject('CLI11')
    CLI11_dep = CLI11_proj.get_variable('CLI11_dep')
endif

threads = dependency('threads')

i2c=meson.get_compiler('cpp').find_library('i2c')
if not i2c.found()
	error('i2c is required')
endif

udev = meson.get_compiler('cpp').find_library('udev')

configure_file(
  copy: true,
  input: 'service_files/xyz.openbmc_project.mctpd@.service',
  install: true,
  install_dir: systemd_system_unit_dir,
  output: 'xyz.openbmc_project.mctpd@.service',
)

deps = [
    boost,
    nlohmann_json_dep,
    threads,
    sdbusplus,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    libmctp_dep,
    CLI11_dep,
    i2c,
    udev
]

src_files = [
    'src/MCTPBinding.cpp',
    'src/hw/aspeed/I3CDriver.cpp',
    'src/hw/aspeed/i3c_utils.cpp',
    'src/hw/aspeed/PCIeMonitor.cpp',
    'src/hw/aspeed/PCIeDriver.cpp',
    'src/hw/DeviceMonitor.cpp',
    'src/hw/PCIeDriver.cpp',
    'src/utils/binding_utils.cpp',
    'src/utils/Configuration.cpp',
    'src/utils/device_watcher.cpp',
    'src/utils/eid_pool.cpp',
    'src/utils/i3c_utils.cpp',
    'src/utils/smbus_utils.cpp',
    'src/utils/transmission_queue.cpp',
    'src/I3CBinding.cpp',
    'src/mctp_bridge.cpp',
    'src/mctp_dbus_interfaces.cpp',
    'src/mctp_device.cpp',
    'src/mctp_endpoint.cpp',
    'src/MCTPBinding.cpp',
    'src/PCIeBinding.cpp',
    'src/routing_table.cpp',
    'src/service_scanner.cpp',
    'src/smbus_bridge.cpp',
    'src/smbus_device.cpp',
    'src/smbus_endpoint.cpp',
    'src/SMBusBinding.cpp',
    'src/unix_sock_intf.cpp', 
]

exe_options = ['warning_level=3']
if yocto_build.enabled()
    exe_options = ['warning_level=3', 'werror=true']
endif

executable(
      'mctpd',
      [src_files, 'src/main.cpp'],
      include_directories : incdir,
      implicit_include_directories: false,
      dependencies: deps,
      install: true,
      install_dir: get_option('bindir'),
      override_options : exe_options

)

if build_tests.enabled()
    gtest_dep = dependency('gtest', required:true)
    gmocktest_dep = dependency('gmock', required:true)
    gtest_main_dep = dependency('gtest_main', required: true)

    common_test_deps = [
        gtest_dep,
        gtest_main_dep,
        gmocktest_dep,
        boost,
        nlohmann_json_dep,
        threads,
        sdbusplus,
        phosphor_dbus_interfaces_dep,
        phosphor_logging_dep,
        libmctp_dep,
        CLI11_dep,
        i2c,
        udev
    ]

    test_incdir = include_directories(
        'include',
        'tests'
    )

    mctp_test_src = [
        'tests/test-binding.cpp',
        'tests/test-mctpd.cpp',
        'tests/test-pcie_binding-devices.cpp',
        'tests/test-pcie_binding-discovery.cpp',
    ]

    mctp_test_exe = executable(
        'mctp_test',
        [src_files, mctp_test_src],
        include_directories: test_incdir,
        dependencies: common_test_deps,
        c_args: ['-std=gnu11'],
        cpp_args: ['-DUSE_MOCK', '-std=c++23']
    )
    test('mctpd test', mctp_test_exe, is_parallel : false)

endif
