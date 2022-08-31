project(
    'mctpd',
    'cpp',
    license: 'Apache-2.0',
    version: '0.1',
    default_options: [
        'warning_level=0',
        'werror=true',
        'cpp_std=c++20'
    ],
)
cpp = meson.get_compiler('cpp')

add_project_arguments(
  cpp.get_supported_arguments([
  '-Wold-style-cast',
  '-Wcast-align',
  '-Wunused',
  '-Woverloaded-virtual',
  '-Wconversion',
  '-Wsign-conversion',
  '-Wno-attributes',
   ]),
  language: 'cpp'
)

add_project_arguments(
  cpp.get_supported_arguments([
    '-Weverything',
    '-Wno-c++98-compat',
    '-Wno-c++98-compat-pedantic',
    '-Wno-global-constructors',
    '-Wno-exit-time-destructors',
    '-Wno-shadow',
    '-Wno-used-but-marked-unused',
    '-Wno-documentation-unknown-command',
    '-Wno-weak-vtables',
    '-Wno-documentation',
    '-Wno-padded',
    '-Wno-pedantic',
    '-Wno-error=pedantic',
    '-Wunused-parameter',
    '-Wcovered-switch-default',
    '-Wcomma',
    '-Wextra-semi',
    '-Wno-zero-as-null-pointer-constant',
    '-Wswitch-enum',
    '-Wnull-dereference',
    '-Wdouble-promotion',
    '-Wno-sign-conversion',
    '-Wno-conversion',
    '-Wno-old-style-cast',
    '-Wno-extra-semi',
    '-Wno-unused-parameter',
    '-Wno-switch-enum',
    '-Wno-overloaded-virtual',
    '-Wall',
    '-Wformat=2',
  ]),
  language:'cpp')

yocto_build = get_option('yocto_dep')

dep_required = false

if yocto_build.enabled()
    dep_required = true
endif

incdir = include_directories(
'include','include/hw','include/utils','include/hw/aspeed'
)

boost = dependency('boost', required: dep_required, version : '>=1.71',
        modules: [ 'coroutine', 'context'])
if not boost.found()
     boost_proj = subproject('boost_1_71_0', required: true)
     boost = boost_proj.get_variable('boost_dep')
endif

sdbusplus = dependency('sdbusplus', required: dep_required)
if not sdbusplus.found()
    sdbusplus_proj = subproject('sdbusplus', required: true)
    sdbusplus = sdbusplus_proj.get_variable('sdbusplus_dep')
endif
sdbusplus_dep = sdbusplus.partial_dependency(link_args: true,
     includes : true, links: true)

if cpp.has_header('phosphor-logging/log.hpp')
    phosphorlog_dep = dependency('phosphor-logging', required: dep_required)
else
    subproject('phosphor-logging', required: true)
    phosphorlog_dep = declare_dependency(
        include_directories: 'subprojects/phosphor-logging'
    )
endif

cmake = import('cmake')

libmctp = dependency('libmctp', required: dep_required)
if not libmctp.found()
    libmctp_proj = cmake.subproject('libmctp', required: true)
    libmctp = libmctp_proj.dependency('mctp_intel')
endif

libmctp_dep = libmctp.partial_dependency(link_args: true,
     includes : true, links: true)
	 
systemd = dependency('systemd', required: dep_required)
systemd_system_unit_dir = systemd.get_pkgconfig_variable(
    'systemdsystemunitdir',
    define_variable: ['prefix', get_option('prefix')])

configure_file(
  copy: true,
  input: 'service_files/xyz.openbmc_project.mctpd@.service',
  install: true,
  install_dir: systemd_system_unit_dir,
  output: 'xyz.openbmc_project.mctpd@.service',
)

if cpp.has_header('nlohmann/json.hpp')
    nlohmann_json = declare_dependency()
    message('nlohmann json already found')
else
    nlohmann_json = dependency('', required: yocto_build.enabled())
    subproject('nlohmann', required: true)
    nlohmann_json = declare_dependency(
        include_directories: [
              'subprojects/nlohmann/single_include',
              'subprojects/nlohmann/single_include/nlohmann'])
endif

cli11_dep = dependency('cli11', required: false)
has_cli11 = meson.get_compiler('cpp').has_header_symbol(
    'CLI/CLI.hpp',
    'CLI::App',
    dependencies: cli11_dep,
    required: false)
if not has_cli11
    cli11_proj = subproject('cli11', required: false)
    assert(cli11_proj.found(), 'CLI11 is required')
    cli11_dep = cli11_proj.get_variable('CLI11_dep')
endif

phosphorlog_dep = dependency('phosphor-logging').partial_dependency(compile_args : false, link_args: true,
     includes : true, links: true)
	 
phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces', required: dep_required)
if not phosphor_dbus_interfaces.found()
    phosphor_dbus_interfaces_proj = subproject('phosphor-dbus-interfaces', required: true)
    phosphor_dbus_interfaces = phosphor_dbus_interfaces_proj.get_variable('phosphor_dbus_interfaces_dep')
endif

phosphor_dbus_interfaces_dep = phosphor_dbus_interfaces.partial_dependency(link_args: true,
     includes : true, links: true)
	  
threads = dependency('threads')

gtest_dep = dependency('gtest', required:dep_required)

i2c=meson.get_compiler('cpp').find_library('i2c')
if not i2c.found()
	error('i2c is required')
endif

udev = meson.get_compiler('cpp').find_library('udev')

deps = [
    boost,
    threads,
    sdbusplus_dep,
    libmctp_dep,
    phosphorlog_dep,
    phosphor_dbus_interfaces_dep,
    i2c,
    udev,
    gtest_dep,
    cli11_dep,
    nlohmann_json
]

# TODO: libmctp linking 

src_files = [
	'src/main.cpp', 
	'src/MCTPBinding.cpp',
	'src/SMBusBinding.cpp',
	'src/PCIeBinding.cpp',
	'src/hw/DeviceMonitor.cpp',
	'src/hw/PCIeDriver.cpp',
	'src/hw/aspeed/PCIeMonitor.cpp',
	'src/hw/aspeed/PCIeDriver.cpp',
	'src/utils/Configuration.cpp',
	'src/utils/device_watcher.cpp',
	'src/utils/transmission_queue.cpp',
	'src/utils/eid_pool.cpp',
	'src/utils/smbus_utils.cpp',
	'src/utils/binding_utils.cpp',
	'src/routing_table.cpp',
	'src/service_scanner.cpp',
	'src/mctp_dbus_interfaces.cpp',
	'src/mctp_device.cpp',
	'src/mctp_endpoint.cpp',
	'src/mctp_bridge.cpp',
	'src/smbus_device.cpp',
	'src/smbus_endpoint.cpp',
	'src/smbus_bridge.cpp',
	'src/I3CBinding.cpp',
	'src/utils/i3c_utils.cpp',
	'src/hw/aspeed/I3CDriver.cpp',
	'src/utils/binding_utils.cpp'
]

exe_options = ['warning_level=3']
if yocto_build.enabled()
    exe_options = ['warning_level=3', 'werror=true']
endif

executable(
      'mctpd',
      src_files,
      include_directories : incdir,
      implicit_include_directories: false,
      dependencies: deps,
      install: true,
      install_dir: get_option('bindir'),
      override_options : exe_options)

