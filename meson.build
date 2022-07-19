project(
    'mctpd',
    'cpp',
    license: 'Apache-2.0',
    version: '0.1',
    default_options: [
        'warning_level=0',
        'werror=true',
        'cpp_std=c++17'
    ],
)

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
	 
threads = dependency('threads')

i2c = meson.get_compiler('cpp').find_library('i2c')

udev = meson.get_compiler('cpp').find_library('udev')

deps = [
    boost,
    threads,
    dependency('libmctp', required: dep_required),
    dependency('phosphor-logging', required: dep_required),
    dependency('sdbusplus', required: dep_required),
    dependency('phosphor-dbus-interfaces', required: dep_required),
    i2c,
    udev
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
	'src/routing_table.cpp',
	'src/service_scanner.cpp',
	'src/mctp_dbus_interfaces.cpp',
	'src/mctp_device.cpp',
	'src/mctp_endpoint.cpp',
	'src/mctp_bridge.cpp',
	'src/smbus_device.cpp',
	'src/smbus_endpoint.cpp',
	'src/smbus_bridge.cpp'
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

