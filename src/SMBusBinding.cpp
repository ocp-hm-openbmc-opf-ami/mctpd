#include "SMBusBinding.hpp"

#include "utils/utils.hpp"

#include <libmctp-smbus.h>

#include <optional>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Inventory/Decorator/I2CDevice/server.hpp>
#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;
using I2CDeviceDecorator =
    sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::I2CDevice;

SMBusBinding::SMBusBinding(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<object_server>& objServer, const std::string& objPath,
    const SMBusConfiguration& conf, boost::asio::io_context& ioc,
    std::shared_ptr<boost::asio::posix::stream_descriptor>&& i2cMuxMonitor) :
    SMBusBridge(conn, objServer, objPath, conf, ioc, std::move(i2cMuxMonitor))
{
    smbusInterface = objServer->add_interface(objPath, smbus_server::interface);

    try
    {
        arpMasterSupport = conf.arpMasterSupport;
        bus = conf.bus;
        bmcSlaveAddr = conf.bmcSlaveAddr;
        supportedEndpointSlaveAddress = conf.supportedEndpointSlaveAddress;
        scanInterval = conf.scanInterval;

        // TODO: If we are not top most busowner, wait for top mostbus owner
        // to issue EID Pool
        if (conf.mode == mctp_server::BindingModeTypes::BusOwner)
        {
            eidPool.initializeEidPool(conf.eidPool);
        }

        if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
        {
            discoveredFlag = DiscoveryFlags::kNotApplicable;
        }
        else
        {
            discoveredFlag = DiscoveryFlags::kUnDiscovered;
            smbusRoutingInterval = conf.routingIntervalSec;
        }

        registerProperty(smbusInterface, "DiscoveredFlag",
                         convertToString(discoveredFlag));
        registerProperty(smbusInterface, "ArpMasterSupport", arpMasterSupport);
        registerProperty(smbusInterface, "BusPath", bus);
        registerProperty(smbusInterface, "BmcSlaveAddress", bmcSlaveAddr);

        if (smbusInterface->initialize() == false)
        {
            throw std::system_error(
                std::make_error_code(std::errc::function_not_supported));
        }
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SMBus Interface init failed",
            phosphor::logging::entry("Exception:", e.what()));
        throw;
    }
}

SMBusBinding::~SMBusBinding()
{
    objectServer->remove_interface(smbusInterface);
}

void SMBusBinding::initializeBinding()
{
    try
    {
        initializeMctp();
        auto rootPort = SMBusInit();
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Scanning root port");
        setMuxIdleMode(MuxIdleModes::muxIdleModeDisconnect);
        muxPortMap = getMuxFds(rootPort);
    }

    catch (const std::exception& e)
    {
        auto error =
            "Failed to initialise SMBus binding: " + std::string(e.what());
        phosphor::logging::log<phosphor::logging::level::ERR>(error.c_str());
        return;
    }

    setupPowerMatch(connection, this);
    setupMuxMonitor();
    if (bindingModeType == mctp_server::BindingModeTypes::BusOwner)
    {
        scanDevices();
    }
}

std::optional<std::string>
    SMBusBinding::getLocationCode(const std::vector<uint8_t>& bindingPrivate)
{
    const std::filesystem::path muxSymlinkDirPath("/dev/i2c-mux");
    auto smbusBindingPvt =
        reinterpret_cast<const mctp_smbus_pkt_private*>(bindingPrivate.data());
    const size_t busNum = getBusNumByFd(smbusBindingPvt->fd);

    if (!std::filesystem::exists(muxSymlinkDirPath) ||
        !std::filesystem::is_directory(muxSymlinkDirPath))
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "/dev/i2c-mux does not exist");
        return std::nullopt;
    }
    for (auto file :
         std::filesystem::recursive_directory_iterator(muxSymlinkDirPath))
    {
        if (!file.is_symlink())
        {
            continue;
        }
        std::string linkPath =
            std::filesystem::read_symlink(file.path()).string();
        if (boost::algorithm::ends_with(linkPath,
                                        "i2c-" + std::to_string(busNum)))
        {
            std::string slotName = file.path().filename().string();
            // Only take the part before "_Mux" in mux name
            std::string muxFullname =
                file.path().parent_path().filename().string();
            std::string muxName =
                muxFullname.substr(0, muxFullname.find("_Mux"));
            std::string location = muxName + ' ' + slotName;
            std::replace(location.begin(), location.end(), '_', ' ');
            return location;
        }
    }
    return std::nullopt;
}

void SMBusBinding::populateDeviceProperties(
    const mctp_eid_t eid, const std::vector<uint8_t>& bindingPrivate,
    const uint8_t nid)
{
    auto smbusBindingPvt =
        reinterpret_cast<const mctp_smbus_pkt_private*>(bindingPrivate.data());

    std::string mctpEpObj = "/xyz/openbmc_project/mctp/device/" +
                            std::to_string(nid) + "/" + std::to_string(eid);

    std::shared_ptr<dbus_interface> smbusIntf;
    smbusIntf =
        objectServer->add_interface(mctpEpObj, I2CDeviceDecorator::interface);
    smbusIntf->register_property<size_t>("Bus",
                                         getBusNumByFd(smbusBindingPvt->fd));
    smbusIntf->register_property<size_t>("Address",
                                         smbusBindingPvt->slave_addr);
    smbusIntf->initialize();
    deviceInterface.emplace(eid, std::move(smbusIntf));
}

std::vector<uint8_t> SMBusBinding::getOwnPhysicalAddress()
{
    return std::vector<uint8_t>{bmcSlaveAddr};
}
