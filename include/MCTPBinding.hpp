#pragma once


#include "routing_table.hpp"
#include "mctp_bridge.hpp"
#include "service_scanner.hpp"
#include "utils/Configuration.hpp"
#include "utils/transmission_queue.hpp"
#include "utils/types.hpp"

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

struct InternalVdmSetDatabase
{
    uint8_t vendorIdFormat;
    uint16_t vendorId;
    uint16_t commandSetType;
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

  protected:
    std::shared_ptr<sdbusplus::asio::connection> connection;
    bool rsvBWActive = false;
    mctp_eid_t reservedEID = 0;
    mctpd::MctpTransmissionQueue transmissionQueue;
    mctpd::DeviceWatcher deviceWatcher{};
    mctpd::EidPool eidPool;
    mctpd::RoutingTable routingTable;
    bridging::MCTPServiceScanner mctpServiceScanner;

    std::unordered_map<uint8_t, version_entry>
        versionNumbersForUpperLayerResponder;

    // vendor PCI Msg Interface
    endpointInterfaceMap vendorIdInterface;
    bridging::MCTPServiceScanner mctpServiceScanner;
    // Register MCTP responder for upper layer
    std::vector<InternalVdmSetDatabase> vdmSetDatabase;

    virtual bool reserveBandwidth(const mctp_eid_t eid, const uint16_t timeout);
    virtual bool releaseBandwidth(const mctp_eid_t eid);
    virtual void triggerDeviceDiscovery();
    virtual bool handleEndpointDiscovery(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleSetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetEndpointId(mctp_eid_t destEid, void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetVersionSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetMsgTypeSupport(mctp_eid_t destEid,
                                         void* bindingPrivate,
                                         std::vector<uint8_t>& request,
                                         std::vector<uint8_t>& response);
    virtual bool handleGetVdmSupport(mctp_eid_t endpointEid,
                                     void* bindingPrivate,
                                     std::vector<uint8_t>& request,
                                     std::vector<uint8_t>& response);
    virtual bool handleGetRoutingTable(const std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response);

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

    bool isMCTPVersionSupported(const MCTPVersionFields& version);
    void logUnsupportedMCTPVersion(
        const std::vector<struct MCTPVersionFields> versionsData,
        const mctp_eid_t eid);
    virtual void
        updateRoutingTableEntry(mctpd::RoutingTable::Entry entry,
                                const std::vector<uint8_t>& privateData);

    // Register MCTP responder for upper layer
    std::vector<InternalVdmSetDatabase> vdmSetDatabase;

  private:
    bool staticEid;
    std::vector<uint8_t> uuid;
    mctp_server::BindingTypes bindingID{};

    void createUuid();
    void clearRegisteredDevice(const mctp_eid_t eid);

    bool isEIDMappedToUUID(mctp_eid_t& eid, std::string& destUUID);
    bool isEIDRegistered(mctp_eid_t eid);
    MctpStatus sendMctpRawPayload(const std::vector<uint8_t>& data);

    void sendRoutingTableEntries(
        const std::vector<mctpd::RoutingTable::Entry::MCTPLibData>& entries,
        std::optional<std::vector<uint8_t>> bindingPrivateData,
        const mctp_eid_t eid = 0);
    void sendNewRoutingTableEntryToAllBridges(
        const mctpd::RoutingTable::Entry& entry);
    void sendRoutingTableEntriesToBridge(
        const mctp_eid_t bridge, const std::vector<uint8_t>& bindingPrivate);
};
    MctpStatus sendMctpRawPayload(const std::vector<uint8_t>& data);
};

