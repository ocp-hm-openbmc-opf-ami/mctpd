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
    bool arpMasterSupport;
    int outFd{-1}; // out_fd for the root bus
    uint8_t bmcSlaveAddr;
    std::string bus;
    std::vector<DeviceTableEntry_t> smbusDeviceTable;
    std::map<int, int> muxPortMap;
    int busOwnerFd;
    uint8_t busOwnerSlaveAddr;
    std::shared_ptr<dbus_interface> smbusInterface;

    std::string SMBusInit();
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

  private:
    int inFd{-1}; // in_fd for the smbus binding
    boost::asio::posix::stream_descriptor smbusReceiverFd;
    struct mctp_binding_smbus* smbus = nullptr;

    void readResponse();
};