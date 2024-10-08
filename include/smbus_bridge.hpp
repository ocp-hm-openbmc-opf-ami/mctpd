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

#include "smbus_endpoint.hpp"

enum class MuxIdleModes : uint8_t
{
    muxIdleModeConnect = 0,
    muxIdleModeDisconnect,
};

enum MuxSkipListAction : uint8_t
{
    stop = 0,
    start,
    disable,
    enable
};

class SMBusBridge : public SMBusEndpoint
{
  public:
    SMBusBridge(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        std::shared_ptr<object_server>& objServer, const std::string& objPath,
        const SMBusConfiguration& conf, boost::asio::io_context& ioc,
        std::shared_ptr<boost::asio::posix::stream_descriptor>&& i2cMuxMonitor);
    SMBusBridge() = delete;
    ~SMBusBridge();
    void triggerDeviceDiscovery() override;

  protected:
    uint64_t scanInterval;
    std::set<uint8_t> supportedEndpointTargetAddress;
    std::set<std::pair<int, uint8_t>> rootDeviceMap;

    void setMuxIdleMode(const MuxIdleModes mode);
    void setupMuxMonitor();
    std::map<std::string, std::string> getMuxPorts();
    std::map<int, int> getMuxFds(const std::string& rootPort);
    void scanDevices();
    void scanPort(const int scanFd,
                  std::set<std::pair<int, uint8_t>>& deviceMap);
    bool skipListPath(const std::vector<uint8_t> /*payload*/) override;
    bool skipListPaths(std::vector<std::string> skipListNames);

    std::set<uint8_t> disabledMuxPortList;
    bool isInMuxSlotDisableList(uint8_t slotNum);
    void updateSkipListSet(std::set<uint8_t>& skipFileSet);
    bool updateSkipListFile(uint8_t muxSlotNumber, uint8_t disableOrEnableMux);

  private:
    size_t ret = 0;
    boost::asio::steady_timer reserveBWTimer;
    boost::asio::steady_timer refreshMuxTimer;
    boost::asio::steady_timer scanTimer;
    std::unordered_map<std::string, std::string> muxIdleModeMap{};
    std::shared_ptr<boost::asio::posix::stream_descriptor> muxMonitor;

    void restoreMuxIdleMode();
    inline void handleMuxInotifyEvent(const std::string& name);
    void monitorMuxChange();
    void scanMuxBus(std::set<std::pair<int, uint8_t>>& deviceMap);
    void initEndpointDiscovery(boost::asio::yield_context& yield);
    bool reserveBandwidth(boost::asio::yield_context yield,
                          const mctp_eid_t eid,
                          const uint16_t timeout) override;
    void startTimerAndReleaseBW(const uint16_t interval,
                                const mctp_smbus_pkt_private prvt);
    bool releaseBandwidth(boost::asio::yield_context yield,
                          const mctp_eid_t eid) override;
    bool getBusNumberFromSlotName(uint8_t& skipSlotNumber,
                                  const std::string& skipSlotName);
};