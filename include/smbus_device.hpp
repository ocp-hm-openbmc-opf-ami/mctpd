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

#pragma once

#include "MCTPBinding.hpp"

#include <libmctp-smbus.h>

#include <phosphor-logging/log.hpp>

// Logical I2C root bus information
struct RootBusInfo
{
    RootBusInfo(boost::asio::io_context& ioc) :
        inFd(-1), outFd(-1), rootPortNo(""), muxPortMap{},
        smbusReceiverFd(ioc){};
    RootBusInfo(const RootBusInfo& other) = delete;
    RootBusInfo& operator=(const RootBusInfo& other) = delete;

    ~RootBusInfo()
    {
        if (inFd >= 0)
        {
            close(inFd);
        }
        if (outFd >= 0)
        {
            close(outFd);
        }
        if (smbusReceiverFd.native_handle() >= 0)
        {
            smbusReceiverFd.release();
        }
    }

    void readResponse(struct mctp_binding_smbus* smbus)
    {
        smbusReceiverFd.async_wait(
            boost::asio::posix::stream_descriptor::wait_error,
            [smbus, this](const boost::system::error_code& ec) {
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("Error: mctp_smbus_read(). RootPortNo: " + rootPortNo)
                            .c_str());
                    readResponse(smbus);
                }

                // through libmctp this will invoke rxMessage and message
                // assembly
                mctp_smbus_read(smbus, inFd, outFd);
                readResponse(smbus);
            });
    }

    int inFd;  // in_fd for root bus and branches (slave-mqueue)
    int outFd; // out_fd for the root bus
    std::string rootPortNo;
    std::map<int /*muxFd*/, int /*muxPort*/> muxPortMap;
    boost::asio::posix::stream_descriptor smbusReceiverFd;
};

using BusPath = std::string;
using DeviceTableEntry_t =
    std::pair<mctp_eid_t /*eid*/,
              struct mctp_smbus_pkt_private /*binding prv data*/>;

class SMBusDevice : public MctpBinding
{
  public:
    SMBusDevice(std::shared_ptr<sdbusplus::asio::connection> conn,
                std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const SMBusConfiguration& conf,
                boost::asio::io_context& ioc);
    SMBusDevice() = delete;
    ~SMBusDevice();
    std::optional<std::vector<uint8_t>>
        getBindingPrivateData(uint8_t dstEid) override;
    void addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                    void* bindingPrivate) override;

  protected:
    std::map<BusPath, std::unique_ptr<RootBusInfo>> rootBusMap;
    bool arpControllerSupport;
    uint8_t bmcTargetAddr;
    std::set<std::string> busses;
    std::vector<DeviceTableEntry_t> smbusDeviceTable;
    int busOwnerFd;
    uint8_t busOwnerTargetAddr;
    std::shared_ptr<dbus_interface> smbusInterface;

    void smbusInit();
    std::unique_ptr<RootBusInfo> rootBusInit(const std::string& bus);
    int getBusNumByFd(const int fd);
    void processRoutingTableChanges(
        const std::vector<DeviceTableEntry_t>& newTable,
        boost::asio::yield_context& yield, const std::vector<uint8_t>& prvData);
    bool isDeviceEntryPresent(
        const DeviceTableEntry_t& deviceEntry,
        const std::vector<DeviceTableEntry_t>& deviceTable);
    bool isDeviceTableChanged(const std::vector<DeviceTableEntry_t>& tableMain,
                              const std::vector<DeviceTableEntry_t>& tableTmp);
    bool isBindingDataSame(const mctp_smbus_pkt_private& dataMain,
                           const mctp_smbus_pkt_private& dataTmp);
    mctp_eid_t
        getEIDFromDeviceTable(const std::vector<uint8_t>& bindingPrivate);
    std::vector<DeviceTableEntry_t>::iterator
        removeDeviceTableEntry(const mctp_eid_t eid);
    uint8_t getTransportId() override;
    std::vector<uint8_t>
        getPhysicalAddress(const std::vector<uint8_t>& bindingPrivate) override;
    std::set<std::string> getRootI2CBusses(std::set<uint8_t> i2cBusNums,
                                           std::set<uint8_t> i3cBusNums);

  private:
    struct mctp_binding_smbus* smbus = nullptr;
    boost::asio::io_context& ioc;
};
