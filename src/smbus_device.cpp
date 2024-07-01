/*
// Copyright (c) 2022 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "smbus_device.hpp"

#include "hw/aspeed/i3c_utils.hpp"
#include "utils/smbus_utils.hpp"
#include "utils/utils.hpp"

#include <fstream>

#include "libmctp-smbus.h"

SMBusDevice::SMBusDevice(std::shared_ptr<sdbusplus::asio::connection> conn,
                         std::shared_ptr<object_server>& objServer,
                         const std::string& objPath,
                         const SMBusConfiguration& conf,
                         boost::asio::io_context& ioc) :
    MctpBinding(conn, objServer, objPath, conf, ioc,
                mctp_server::BindingTypes::MctpOverSmbus),
    ioc(ioc)
{
}

SMBusDevice::~SMBusDevice()
{
    rootBusMap.clear();
    mctp_smbus_free(smbus);
}

void SMBusDevice::smbusInit()
{
    smbus = mctp_smbus_init();
    if (smbus == nullptr)
    {
        throwRunTimeError("Error in mctp smbus init");
    }

    if (mctp_smbus_register_bus(smbus, mctp, ownEid) != 0)
    {
        throwRunTimeError("Error in SMBus binding registration");
    }

    mctp_set_rx_all(mctp, &MctpBinding::rxMessage,
                    static_cast<MctpBinding*>(this));
    mctp_set_rx_raw(mctp, &MctpBinding::onRawMessage);
    mctp_set_rx_ctrl(mctp, &MctpBinding::handleMCTPControlRequests,
                     static_cast<MctpBinding*>(this));

    // Source target address is in 8 bit format and should always be an odd
    // number
    mctp_smbus_set_src_target_addr(smbus, bmcTargetAddr | 0x01);
}

std::unique_ptr<RootBusInfo> SMBusDevice::rootBusInit(const std::string& bus)
{
    auto busInfo = std::make_unique<RootBusInfo>(ioc);
    std::string rootPort;

    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in opening smbus root port");
    }
    busInfo->rootPortNo = rootPort;

    std::stringstream addrStream;
    addrStream.str("");

    int addr7bit = (bmcTargetAddr >> 1);

    // want the format as 0x0Y
    addrStream << std::setfill('0') << std::setw(2) << std::hex << addr7bit;

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Target Address " + addrStream.str()).c_str());

    // MSB fixed to 10 so hex is 0x10XX ~ 0x1005
    std::string hexTargetAddr("10");
    hexTargetAddr.append(addrStream.str());

    std::string inputDevice = "/sys/bus/i2c/devices/" + rootPort + "-" +
                              hexTargetAddr + "/slave-mqueue";

    busInfo->inFd =
        open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    // Doesn't exist, try to create one
    if (busInfo->inFd < 0)
    {
        std::string newInputDevice =
            "/sys/bus/i2c/devices/i2c-" + rootPort + "/new_device";
        std::string para("slave-mqueue 0x");
        para.append(hexTargetAddr);

        std::fstream deviceFile;
        deviceFile.open(newInputDevice, std::ios::out);
        deviceFile << para;
        deviceFile.close();
        busInfo->inFd =
            open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

        if (busInfo->inFd < 0)
        {
            throwRunTimeError("Error in opening smbus binding in_bus");
        }
    }

    // Open root bus
    busInfo->outFd = open(bus.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (busInfo->outFd < 0)
    {
        throwRunTimeError("Error in opening smbus binding out bus");
    }

    busInfo->smbusReceiverFd.assign(busInfo->inFd);
    busInfo->readResponse(smbus);

    return busInfo;
}

std::optional<std::vector<uint8_t>>
    SMBusDevice::getBindingPrivateData(uint8_t dstEid)
{
    mctp_smbus_pkt_private prvt = {};

    for (auto& device : smbusDeviceTable)
    {
        if (std::get<0>(device) == dstEid)
        {
            mctp_smbus_pkt_private temp = std::get<1>(device);
            prvt.fd = temp.fd;
            auto it = std::find_if(rootBusMap.begin(), rootBusMap.end(),
                                   [&prvt](const auto& rootBus) {
                                       const auto& rootBusInfo = rootBus.second;
                                       return rootBusInfo->muxPortMap.count(
                                                  prvt.fd) > 0;
                                   });
            if (it != rootBusMap.end())
            {
                prvt.mux_hold_timeout = 1000;
                prvt.mux_flags = IS_MUX_PORT;
            }
            else
            {
                prvt.mux_hold_timeout = 0;
                prvt.mux_flags = 0;
            }
            prvt.target_addr = temp.target_addr;
            uint8_t* prvtPtr = reinterpret_cast<uint8_t*>(&prvt);
            return std::vector<uint8_t>(prvtPtr, prvtPtr + sizeof(prvt));
        }
    }
    return std::nullopt;
}

int SMBusDevice::getBusNumByFd(const int fd)
{
    auto it = std::find_if(rootBusMap.begin(), rootBusMap.end(),
                           [fd](const auto& rootBus) {
                               const auto& rootBusInfo = rootBus.second;
                               return rootBusInfo->muxPortMap.count(fd) > 0;
                           });
    if (it != rootBusMap.end())
    {
        return it->second->muxPortMap.at(fd);
    }

    it = std::find_if(rootBusMap.begin(), rootBusMap.end(),
                      [fd](const auto& rootBus) {
                          const auto& rootBusInfo = rootBus.second;
                          return rootBusInfo->outFd == fd;
                      });
    if (it != rootBusMap.end())
    {
        return std::stoi(it->second->rootPortNo);
    }

    // bus cannot be negative, return -1 on error
    return -1;
}

std::vector<DeviceTableEntry_t>::iterator
    SMBusDevice::removeDeviceTableEntry(const mctp_eid_t eid)
{
    return smbusDeviceTable.erase(
        std::remove_if(smbusDeviceTable.begin(), smbusDeviceTable.end(),
                       [eid](auto const& tableEntry) {
                           return (tableEntry.first == eid);
                       }),
        smbusDeviceTable.end());
}

mctp_eid_t SMBusDevice::getEIDFromDeviceTable(
    const std::vector<uint8_t>& bindingPrivate)
{
    mctp_eid_t eid = MCTP_EID_NULL;
    for (auto& deviceEntry : smbusDeviceTable)
    {
        const mctp_smbus_pkt_private* ptr =
            reinterpret_cast<const mctp_smbus_pkt_private*>(
                bindingPrivate.data());
        mctp_smbus_pkt_private bindingDataEntry = std::get<1>(deviceEntry);
        if (bindingDataEntry.target_addr == ptr->target_addr &&
            bindingDataEntry.fd == ptr->fd)
        {
            eid = std::get<0>(deviceEntry);
            break;
        }
    }
    return eid;
}

void SMBusDevice::addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                             void* bindingPrivate)
{
    if (bindingPrivate == nullptr)
    {
        return;
    }

    auto deviceIter = std::find_if(
        smbusDeviceTable.begin(), smbusDeviceTable.end(),
        [eid](auto const eidEntry) { return std::get<0>(eidEntry) == eid; });

    if (deviceIter != smbusDeviceTable.end())
    {
        return;
    }

    auto bindingPtr = reinterpret_cast<mctp_smbus_pkt_private*>(bindingPrivate);

    struct mctp_smbus_pkt_private smbusBindingPvt = {};
    smbusBindingPvt.fd = bindingPtr->fd;
    smbusBindingPvt.mux_hold_timeout = bindingPtr->mux_hold_timeout;
    smbusBindingPvt.mux_flags = bindingPtr->mux_flags;
    smbusBindingPvt.target_addr =
        static_cast<uint8_t>((bindingPtr->target_addr) & (~1));

    smbusDeviceTable.emplace_back(std::make_pair(eid, smbusBindingPvt));

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("New EID added to device table. EID = " + std::to_string(eid))
            .c_str());
}

bool SMBusDevice::isBindingDataSame(const mctp_smbus_pkt_private& dataMain,
                                    const mctp_smbus_pkt_private& dataTmp)
{
    if (std::tie(dataMain.fd, dataMain.target_addr) ==
        std::tie(dataTmp.fd, dataTmp.target_addr))
    {
        return true;
    }
    return false;
}

bool SMBusDevice::isDeviceTableChanged(
    const std::vector<DeviceTableEntry_t>& tableMain,
    const std::vector<DeviceTableEntry_t>& tableTmp)
{
    if (tableMain.size() != tableTmp.size())
    {
        return true;
    }
    for (size_t i = 0; i < tableMain.size(); i++)
    {
        if ((std::get<0>(tableMain[i]) != std::get<0>(tableTmp[i])) ||
            (!isBindingDataSame(std::get<1>(tableMain[i]),
                                std::get<1>(tableTmp[i]))))
        {
            return true;
        }
    }
    return false;
}

bool SMBusDevice::isDeviceEntryPresent(
    const DeviceTableEntry_t& deviceEntry,
    const std::vector<DeviceTableEntry_t>& deviceTable)
{
    for (size_t i = 0; i < deviceTable.size(); i++)
    {
        if (std::get<0>(deviceTable[i]) == std::get<0>(deviceEntry))
        {
            return true;
        }
    }
    return false;
}

/* Function takes new routing table, detect changes and creates or removes
 * device interfaces on dbus.
 */
void SMBusDevice::processRoutingTableChanges(
    const std::vector<DeviceTableEntry_t>& newTable,
    boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData)
{
    /* find removed endpoints, in case entry is not present
     * in the newly read routing table remove dbus interface
     * for this device
     */
    for (auto& deviceTableEntry : smbusDeviceTable)
    {
        if (!isDeviceEntryPresent(deviceTableEntry, newTable))
        {
            unregisterEndpoint(std::get<0>(deviceTableEntry));
        }
    }

    /* find new endpoints, in case entry is in the newly read
     * routing table but not present in the routing table stored as
     * the class member, register new dbus device interface
     */
    for (auto& deviceTableEntry : newTable)
    {
        if (!isDeviceEntryPresent(deviceTableEntry, smbusDeviceTable))
        {
            registerEndpoint(yield, prvData, std::get<0>(deviceTableEntry),
                             mctp_server::BindingModeTypes::Endpoint);
        }
    }
}

uint8_t SMBusDevice::getTransportId()
{
    return MCTP_BINDING_SMBUS;
}

std::vector<uint8_t>
    SMBusDevice::getPhysicalAddress(const std::vector<uint8_t>& privateData)
{
    auto smbusData =
        reinterpret_cast<const mctp_smbus_pkt_private*>(privateData.data());
    return std::vector<uint8_t>{smbusData->target_addr};
}

std::set<std::string>
    SMBusDevice::getRootI2CBusses(std::set<uint8_t> i2cBusNums,
                                  std::set<uint8_t> i3cBusNums)
{

    const std::string devDir = "/dev/i2c-";

    std::set<std::string> i2cRootDevBusses;
    // Directly create i2c root bus dev paths from i2c bus numbers
    for (const auto& i2cBusNum : i2cBusNums)
    {
        i2cRootDevBusses.insert(devDir + std::to_string(i2cBusNum));
    }

    // Find i2c bus ports behind hub
    std::set<uint8_t> i2cRootBussesBehindHub;
    for (const auto& i3cBusNum : i3cBusNums)
    {
        auto rootBusTemp = hw::aspeed::getI2CPortsOnHub(i3cBusNum);
        i2cRootBussesBehindHub.insert(rootBusTemp.begin(), rootBusTemp.end());
    }
    for (const auto& i2cBusNum : i2cRootBussesBehindHub)
    {
        i2cRootDevBusses.insert(devDir + std::to_string(i2cBusNum));
    }

    for (auto const& bus : i2cRootDevBusses)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("Root i2c bus found: " + bus).c_str());
    }
    return i2cRootDevBusses;
}
