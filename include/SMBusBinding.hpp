#pragma once

#include "smbus_bridge.hpp"

class SMBusBinding : public SMBusBridge
{
  public:
    SMBusBinding(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        std::shared_ptr<object_server>& objServer, const std::string& objPath,
        const SMBusConfiguration& conf, boost::asio::io_context& ioc,
        std::shared_ptr<boost::asio::posix::stream_descriptor>&& i2cMuxMonitor);
    SMBusBinding() = delete;
    ~SMBusBinding() override;
    void initializeBinding() override;
    void populateDeviceProperties(const mctp_eid_t eid,
                                  const std::vector<uint8_t>& bindingPrivate,
                                  const uint8_t nid) override;
    std::optional<std::string>
        getLocationCode(const std::vector<uint8_t>& bindingPrivate) override;
    std::vector<uint8_t> getOwnPhysicalAddress() override;
};
