/*
// Copyright (c) 2023 Intel Corporation
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

#include "mctp_bridge.hpp"
#include "service_scanner.hpp"
#include "utils/Configuration.hpp"
#include "utils/transmission_queue.hpp"
#include "utils/types.hpp"
#include "utils/wait_cond.hpp"

#include <libmctp-cmds.h>

#include <numeric>
#include <unordered_set>

class SMBusBinding;
class PCIeBinding;

constexpr uint8_t vendorIdNoMoreSets = 0xff;

enum MctpStatus
{
    mctpErrorOperationNotAllowed = -5,
    mctpErrorReleaseBWFailed = -4,
    mctpErrorRsvBWIsNotActive = -3,
    mctpErrorRsvBWFailed = -2,
    mctpInternalError = -1,
    mctpSuccess = 0
};

class MctpBinding : public MCTPBridge
{
  public:
    MctpBinding(std::shared_ptr<sdbusplus::asio::connection> conn,
                std::shared_ptr<object_server>& objServer,
                const std::string& objPath, const Configuration& conf,
                boost::asio::io_context& ioc,
                const mctp_server::BindingTypes bindingType);
    MctpBinding() = delete;
    virtual ~MctpBinding() = default;
    virtual void initializeBinding() = 0;
    virtual bool skipListPath(std::vector<uint8_t> /*payload*/);

  protected:
    bool rsvBWActive = false;
    mctp_eid_t reservedEID = 0;
    mctpd::MctpTransmissionQueue transmissionQueue;
    bridging::MCTPServiceScanner mctpServiceScanner;
    WaitCondition regInProgress;
    bool isResetReachable = true;
    static inline constexpr boost::posix_time::millisec regTimeout =
        boost::posix_time::millisec(1500);

    virtual bool reserveBandwidth(boost::asio::yield_context yield,
                                  const mctp_eid_t eid, const uint16_t timeout);
    virtual bool releaseBandwidth(boost::asio::yield_context yield,
                                  const mctp_eid_t eid);
    virtual void triggerDeviceDiscovery();
    virtual void addUnknownEIDToDeviceTable(const mctp_eid_t eid,
                                            void* bindingPrivate);

    void initializeMctp();
    bool registerUpperLayerResponder(uint8_t typeNo,
                                     std::vector<uint8_t>& list);
    bool manageVersionInfo(uint8_t typeNo, std::vector<uint8_t>& list);
    bool manageVdpciVersionInfo(uint16_t vendorId, uint16_t cmdSetType);
    std::optional<mctp_eid_t>
        registerEndpoint(boost::asio::yield_context& yield,
                         const std::vector<uint8_t>& bindingPrivate,
                         mctp_eid_t eid,
                         mctp_server::BindingModeTypes bindingMode =
                             mctp_server::BindingModeTypes::Endpoint);
    void clearRegisteredDevice(const mctp_eid_t eid);
    // MCTP Callbacks
    static void rxMessage(uint8_t srcEid, void* data, void* msg, size_t len,
                          bool tagOwner, uint8_t msgTag, void* bindingPrivate);
    // Handler for bridging packets.
    static void onRawMessage(void* data, void* msg, size_t len,
                             void* msgBindingPrivate);
    static void handleMCTPControlRequests(uint8_t srcEid, void* data, void* msg,
                                          size_t len, bool tagOwner,
                                          uint8_t msgTag, void* bindingPrivate);
    template <typename Interface, typename PropertyType>
    void registerProperty(Interface ifc, const std::string& name,
                          const PropertyType& property,
                          sdbusplus::asio::PropertyPermission access =
                              sdbusplus::asio::PropertyPermission::readOnly)
    {
        if (ifc->register_property(name, property, access) != true)
        {
            throw std::invalid_argument(name);
        }
    }
    bool setMediumId(uint8_t value,
                     mctp_server::MctpPhysicalMediumIdentifiers& mediumId);

    virtual bool setEIDPool(const uint8_t startEID, const uint8_t poolSize);
    void onNewService(const std::string& serviceName);
    virtual void onEIDPool();

  private:
    bool staticEid;
    mctp_server::BindingTypes bindingID{};

    void createUuid();
    MctpStatus sendMctpRawPayload(const std::vector<uint8_t>& data);
};
