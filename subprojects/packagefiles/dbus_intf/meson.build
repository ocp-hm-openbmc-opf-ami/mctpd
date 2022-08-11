project('phosphor-dbus-interfaces', 'cpp',
    meson_version: '>= 0.58.0',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++20',
        'warning_level=3',
        'werror=true',
        'generate_md=' + (meson.is_subproject() ? 'false' : 'true'),
    ],
    version: '1.0.0',
)

#r = run_command('git', 'apply', '0007-ipmi-set-BIOS-id.patch', check: true)
#assert(r.returncode() == 0, 'Applying ipmi-set-BIOS-id patch failed')
#r = run_command('git', 'apply', '0010-Increase-the-default-watchdog-timeout-value.patch', check: true)
#assert(r.returncode() == 0, 'Applying Increase-the-default-watchdog-timeout-value patch failed')
#r = run_command('git', 'apply', '0012-Add-RestoreDelay-interface-for-power-restore-delay.patch', check: true)
#assert(r.returncode() == 0, 'Add-RestoreDelay-interface-for-power-restore-delay patch failed')
#r = run_command('git', 'apply', '0013-Add-ErrConfig.yaml-interface-for-processor-error-config.patch', check: true)
#assert(r.returncode() == 0, 'Add-ErrConfig.yaml-interface-for-processor-error-config patch failed')
#r = run_command('git', 'apply', '0024-Add-the-pre-timeout-interrupt-defined-in-IPMI-spec.patch', check: true)
#assert(r.returncode() == 0, 'Add-the-pre-timeout-interrupt-defined-in-IPMI-spec patch failed')
#r = run_command('git', 'apply', '0025-Add-PreInterruptFlag-properity-in-DBUS.patch', check: true)
#assert(r.returncode() == 0, 'Add-PreInterruptFlag-properity-in-DBUS patch failed')
#r = run_command('git', 'apply', '0026-Add-StandbySpare-support-for-software-inventory.patch', check: true)
#assert(r.returncode() == 0, 'Add-StandbySpare-support-for-software-inventory')
r = run_command('git', 'apply', '0028-MCTP-Daemon-D-Bus-interface-definition.patch', check: true)
assert(r.returncode() == 0, 'Applying MCTP-Daemon-D-Bus-interface-definition patch failed')
#r = run_command('git', 'apply', '0029-Add-D-Bus-interfaces-for-PLDM-FW-update.patch', check: true)
#assert(r.returncode() == 0, 'Add-D-Bus-interfaces-for-PLDM-FW-update patch failed')
#r = run_command('git', 'apply', '0030-Add-PLDM-version-purpose-enumeration.patch', check: true)
#assert(r.returncode() == 0, 'Add-PLDM-version-purpose-enumeration patch failed')
#r = run_command('git', 'apply', '0031-update-meson-build-files-for-control-and-bios.patch', check: true)
#assert(r.returncode() == 0, 'update-meson-build-files-for-control-and-bios patch failed')
r = run_command('git', 'apply', '0032-update-meson-build-for-MCTP-interfaces.patch', check: true)
assert(r.returncode() == 0, 'Applying MCTP-interfaces patch failed')
#r = run_command('git', 'apply', '0033-update-meson-build-for-PLDM-FWU-interfaces.patch', check: true)
#assert(r.returncode() == 0, 'update-meson-build-for-PLDM-FWU-interfaces patch failed')
#r = run_command('git', 'apply', '0034-Add-username-property-to-SessionInfo-interface.patch', check: true)
#assert(r.returncode() == 0, 'Add-username-property-to-SessionInfo-interface patch failed')
r = run_command('git', 'apply', '0035-Add-I3C-Binding-related-interfaces.patch', check: true)
assert(r.returncode() == 0, 'Applying I3C-Binding-related-interfaces patch failed')
r = run_command('git', 'apply', '0036-edit-maxint.patch', check: true)
assert(r.returncode() == 0, 'Applying edit int max patch')

# Get sdbusplus dependency.
sdbusplus_dep = dependency('sdbusplus', required: false)
if sdbusplus_dep.found() and sdbusplus_dep.type_name() != 'internal'
    sdbusplusplus_prog = find_program('sdbus++', native: true)
    sdbuspp_gen_meson_prog = find_program('sdbus++-gen-meson', native: true)
else
    sdbusplus_proj = subproject('sdbusplus', required: true)
    sdbusplus_dep = sdbusplus_proj.get_variable('sdbusplus_dep')
    sdbusplusplus_prog = sdbusplus_proj.get_variable('sdbusplusplus_prog')
    sdbuspp_gen_meson_prog = sdbusplus_proj.get_variable(
        'sdbuspp_gen_meson_prog'
    )
endif

# Parse options to determine appropriate subdirectories to support.
selected_subdirs =['xyz/openbmc_project/Ipmi/SessionInfo','xyz/openbmc_project/Ipmi','xyz/openbmc_project/PLDM','xyz/openbmc_project/PLDM/FWU','xyz/openbmc_project/PLDM/FWU/PnPDescriptor','xyz/openbmc_project/PLDM/FWU/PendingComponentInfo','xyz/openbmc_project/PLDM/FWU/PendingComponentImageSetInfo','xyz/openbmc_project/Inventory/Item','xyz/openbmc_project/Inventory/Item/Bios','xyz/openbmc_project/Control/Processor','xyz/openbmc_project/Control/Processor/ErrConfig','xyz/openbmc_project/Control/Power','xyz/openbmc_project/Software/Version','xyz/openbmc_project/Software/Version','xyz/openbmc_project/PLDM/FWU/','xyz/openbmc_project/PLDM/FWU/PnPDescriptor','xyz/openbmc_project/PLDM/FWU/PendingComponentImageSetInfo','xyz/openbmc_project/PLDM/FWU/PCIDescriptor','xyz/openbmc_project/PLDM/FWU/IANADescriptor','xyz/openbmc_project/PLDM/FWU/FWUBase','xyz/openbmc_project/PLDM/FWU/ComponentActivationMethods','xyz/openbmc_project/PLDM/FWU/CapabilitiesDuringUpdate','xyz/openbmc_project/PLDM/FWU/ActiveComponentInfo','xyz/openbmc_project/PLDM/FWU/ActiveComponentImageSetInfo','xyz/openbmc_project/PLDM/FWU/ACPIDescriptor','xyz/openbmc_project/Software/Activation','xyz/openbmc_project/Control/Processor/ErrConfig','xyz/openbmc_project/Control/Power/RestoreDelay','xyz/openbmc_project/State/Watchdog','xyz/openbmc_project/Inventory/Item/Bios','xyz/openbmc_project/MCTP/Binding/I3C','xyz/openbmc_project/MCTP/Base','xyz/openbmc_project/MCTP/Binding/PCIe','xyz/openbmc_project/MCTP/Binding/SMBus','xyz/openbmc_project/MCTP/Base/Binding','xyz/openbmc_project/MCTP/BusOwner','xyz/openbmc_project/MCTP/SupportedMessageTypes']

selected_subdirs = ['xyz/openbmc_project/MCTP', 'xyz/openbmc_project/Inventory', 'xyz/openbmc_project/Common']

# Install the selected YAML files.
inst_yaml_dir = get_option('datadir') / 'phosphor-dbus-yaml/yaml'
foreach d : selected_subdirs
    install_subdir(
        'yaml' / d,
        install_dir: inst_yaml_dir / d,
        strip_directory: true,
    )
endforeach

# If libphosphor_dbus was not enabled, exit out from here.  We installed
# the YAML which is all we are asked to do.
if not get_option('libphosphor_dbus')
    subdir_done()
endif

generated_sources = []
generated_others = []
yaml_sources = []

# Source the generated meson files.
subdir('gen')
foreach d : selected_subdirs
  subdir('gen' / d)
endforeach
custom_target(
    'md',
    command: 'true',
    output: 'md',
    capture: true,
    depends: generated_others,
    build_by_default: get_option('generate_md'))

generated_files_headers = []
generated_files_cpp = []
foreach s : generated_sources
    foreach f : s.to_list()
        p = f.full_path()
        if p.endswith('.hpp')
            generated_files_headers += f
        elif p.endswith('.cpp')
            generated_files_cpp += f
        else
            error('Unknown filetype: ' + p)
        endif
    endforeach
endforeach

generated_root = meson.current_build_dir() / 'gen/'
exclude_cpp = []
foreach f : generated_files_cpp
    exclude_cpp += f.full_path().replace(generated_root, '').strip('/')
endforeach

# Install the generated header files.
exclude = exclude_cpp
foreach o : generated_others
    foreach f : o.to_list()
        exclude += f.full_path().replace(generated_root, '').strip('/')
    endforeach
endforeach
install_subdir(
    generated_root,
    exclude_files: exclude,
    install_dir: get_option('includedir'),
    strip_directory: true,
)

# Install the generated markdown files.
exclude = exclude_cpp
foreach f : generated_files_headers
    exclude += f.full_path().replace(generated_root, '').strip('/')
endforeach
install_subdir(
    generated_root,
    exclude_files: exclude,
    install_dir: get_option('datadir') / 'doc' / meson.project_name(),
    strip_directory: true,
)

# Define and build libphosphor_dbus.so from the C++ files.
libphosphor_dbus = library(
    'phosphor_dbus',
    generated_sources,
    implicit_include_directories: false,
    include_directories: include_directories('gen'),
    dependencies: sdbusplus_dep,
    version: meson.project_version(),
    install: true,
)

import('pkgconfig').generate(
    libphosphor_dbus,
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'Generated sdbusplus bindings for phosphor-dbus-interfaces',
    variables: ['yamldir=' + '${pc_sysrootdir}${prefix}' / inst_yaml_dir],
)

phosphor_dbus_interfaces_dep = declare_dependency(
    sources: generated_files_headers,
    include_directories: include_directories('gen'),
    link_with: libphosphor_dbus,
    dependencies: sdbusplus_dep,
    variables: ['yamldir=' + meson.project_source_root() / 'yaml'],
) 