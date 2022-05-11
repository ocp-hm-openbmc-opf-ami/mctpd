#include "hw/aspeed/I3CDriver.hpp"

namespace hw
{
namespace aspeed
{

I3CDriver::I3CDriver(boost::asio::io_context& ioc, int fd) : streamMonitor(ioc)
{
    /* TODO: Add logic based on I3C configurations to assign
    streamMonitor's fd */

    streamMonitorFd = fd;
    streamMonitor = boost::asio::posix::stream_descriptor(ioc, streamMonitorFd);
}

void I3CDriver::init()
{
    i3c = mctp_asti3c_init();
    if (i3c == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error in MCTP I3C init");
        throw std::system_error(
            std::make_error_code(std::errc::not_enough_memory));
    }
}

mctp_binding* I3CDriver::binding()
{
    return &i3c->binding;
}

void I3CDriver::pollRx()
{
    streamMonitor.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        [this](const boost::system::error_code& ec) {
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("Error reading PCIe response" + ec.message()).c_str());
                return;
                // pollRx();
            }
            mctp_asti3c_rx(i3c, streamMonitorFd);
            pollRx();
        });
}

bool I3CDriver::setEndpointMap(std::vector<I3CEidInfo>& /*endpoints*/)
{
    //TODO: Kernel needs to expose UAPI to set endpoint map
    return true;
}

I3CDriver::~I3CDriver()
{
    streamMonitor.release();

    if (i3c)
    {
        mctp_asti3c_free(i3c);
    }
}

} // namespace aspeed
} // namespace hw