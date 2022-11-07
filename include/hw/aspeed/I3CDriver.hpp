#pragma once

#include "hw/I3CDriver.hpp"

#include <libmctp-asti3c.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <optional>
#include <phosphor-logging/log.hpp>

namespace hw
{

namespace aspeed
{

class I3CDriver : public hw::I3CDriver
{
  public:
    I3CDriver(boost::asio::io_context& ioc, uint8_t i3cBusNum,
              std::optional<uint8_t> cpuPidMask = 0);
    ~I3CDriver() override;

    void init() override;
    void pollRx() override;
    mctp_binding* binding() override;
    int getDriverFd() override;
    uint8_t getOwnAddress() override;
    uint8_t getDeviceAddress() override;

  private:
    boost::asio::posix::stream_descriptor streamMonitor;
    int streamMonitorFd;
    mctp_binding_asti3c* i3c{};
    bool isController = false;
    std::string i3cDeviceFile;
    std::optional<uint8_t> pidMask;
    uint8_t busNum;
    void discoverI3CDevices();
    void rescanI3CBus();
};

} // namespace aspeed
} // namespace hw