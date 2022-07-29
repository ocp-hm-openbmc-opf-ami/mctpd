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
    smbusReceiverFd(ioc)
{
}

SMBusDevice::~SMBusDevice()
{
    if (smbusReceiverFd.native_handle() >= 0)
    {
        smbusReceiverFd.release();
    }
    if (inFd >= 0)
    {
        close(inFd);
    }
    if (outFd >= 0)
    {
        close(outFd);
    }
    mctp_smbus_free(smbus);
}

std::string SMBusDevice::SMBusInit()
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
    std::string rootPort;

    if (!getBusNumFromPath(bus, rootPort))
    {
        throwRunTimeError("Error in opening smbus rootport");
    }

    std::stringstream addrStream;
    addrStream.str("");

    int addr7bit = (bmcSlaveAddr >> 1);

    // want the format as 0x0Y
    addrStream << std::setfill('0') << std::setw(2) << std::hex << addr7bit;

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("Slave Address " + addrStream.str()).c_str());

    // MSB fixed to 10 so hex is 0x10XX ~ 0x1005
    std::string hexSlaveAddr("10");
    hexSlaveAddr.append(addrStream.str());

    std::string inputDevice = "/sys/bus/i2c/devices/" + rootPort + "-" +
                              hexSlaveAddr + "/slave-mqueue";

    // Source slave address is in 8 bit format and should always be an odd
    // number
    mctp_smbus_set_src_slave_addr(smbus, bmcSlaveAddr | 0x01);

    inFd = open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

    // Doesn't exist, try to create one
    if (inFd < 0)
    {
        std::string newInputDevice =
            "/sys/bus/i2c/devices/i2c-" + rootPort + "/new_device";
        std::string para("slave-mqueue 0x");
        para.append(hexSlaveAddr);

        std::fstream deviceFile;
        deviceFile.open(newInputDevice, std::ios::out);
        deviceFile << para;
        deviceFile.close();
        inFd = open(inputDevice.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

        if (inFd < 0)
        {
            throwRunTimeError("Error in opening smbus binding in_bus");
        }
    }

    // Open root bus
    outFd = open(bus.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (outFd < 0)
    {
        throwRunTimeError("Error in opening smbus binding out bus");
    }
    mctp_smbus_set_in_fd(smbus, inFd);
    mctp_smbus_set_out_fd(smbus, outFd);

    smbusReceiverFd.assign(inFd);
    readResponse();
    return rootPort;
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
            if (muxPortMap.count(prvt.fd) != 0)
            {
                prvt.mux_hold_timeout = 1000;
                prvt.mux_flags = IS_MUX_PORT;
            }
            else
            {
                prvt.mux_hold_timeout = 0;
                prvt.mux_flags = 0;
            }
            prvt.slave_addr = temp.slave_addr;
            uint8_t* prvtPtr = reinterpret_cast<uint8_t*>(&prvt);
            return std::vector<uint8_t>(prvtPtr, prvtPtr + sizeof(prvt));
        }
    }
    return std::nullopt;
}

int SMBusDevice::getBusNumByFd(const int fd)
{
    if (muxPortMap.count(fd))
    {
        return muxPortMap.at(fd);
    }

    std::string busNum;
    if (getBusNumFromPath(bus, busNum))
    {
        return std::stoi(busNum);
    }

    // bus cannot be negative, return -1 on error
    return -1;
}

void SMBusDevice::readResponse()
{
    smbusReceiverFd.async_wait(
        boost::asio::posix::descriptor_base::wait_error, [this](auto& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error: mctp_smbus_read()");
                readResponse();
            }
            // through libmctp this will invoke rxMessage and message assembly
            mctp_smbus_read(smbus);
            readResponse();
        });
}

void SMBusDevice::removeDeviceTableEntry(const mctp_eid_t eid)
{
    smbusDeviceTable.erase(std::remove_if(smbusDeviceTable.begin(),
                                          smbusDeviceTable.end(),
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
        if (bindingDataEntry.slave_addr == ptr->slave_addr &&
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
    smbusBindingPvt.slave_addr =
        static_cast<uint8_t>((bindingPtr->slave_addr) & (~1));

    smbusDeviceTable.emplace_back(std::make_pair(eid, smbusBindingPvt));

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("New EID added to device table. EID = " + std::to_string(eid))
            .c_str());
}

bool SMBusDevice::isBindingDataSame(const mctp_smbus_pkt_private& dataMain,
                                    const mctp_smbus_pkt_private& dataTmp)
{
    if (std::tie(dataMain.fd, dataMain.slave_addr) ==
        std::tie(dataTmp.fd, dataTmp.slave_addr))
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
    return std::vector<uint8_t>{smbusData->slave_addr};
}
