#include<gtest/gtest.h>
#include<gmock/gmock.h>

#include <memory> 
#include <sdbusplus/asio/connection.hpp>
#include <xyz/openbmc_project/MCTP/Binding/SMBus/server.hpp>

#include "PCIeBinding.hpp"
#include "SMBusBinding.hpp"
#include "mocks/objectServerMock.hpp"

using ::testing::_;
using ::testing::An;
using ::testing::Eq;
using ::testing::Return;
using ::testing::StrEq;

using smbus_server =
    sdbusplus::xyz::openbmc_project::MCTP::Binding::server::SMBus;

class MctpdBaseTest : public ::testing::Test
{
  public:
    void SetUp() override
    {
        bus = std::make_shared<mctpd_mock::object_server_mock>();

        // Create iface beforehand, to intercept calls
        uuidIntface =
            bus->backdoor.add_interface(mctpBaseObj, "xyz.openbmc_project.Common.UUID");

        mctpInterface =
            bus->backdoor.add_interface(mctpBaseObj, mctp_server::interface);

        smbusInterface =
            bus->backdoor.add_interface(mctpBaseObj, smbus_server::interface);
    }

    void TearDown() override
    {
    }

    void MakeSmbusConfiguration(
        mctp_server::MctpPhysicalMediumIdentifiers mediumId,
        mctp_server::BindingModeTypes mode, uint8_t defaultEid,
        std::set<uint8_t> eidPool, std::string busName)
    {
        smbusConfig.mediumId = mediumId;
        smbusConfig.mode = mode;
        smbusConfig.defaultEid = defaultEid;
        smbusConfig.eidPool = eidPool;
        smbusConfig.bus = busName;
    }
    std::string mctpBaseObj = "/xyz/openbmc_project/mctp";
    SMBusConfiguration smbusConfig;

    std::shared_ptr<mctpd_mock::object_server_mock> bus;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> uuidIntface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> mctpInterface;
    std::shared_ptr<mctpd_mock::dbus_interface_mock> smbusInterface;
};

/*
 * Check if properties for Base interface
 * are registered, property permission is always
 * set to readOnly and interface initialize method
 * is invoked.
 */
TEST_F(MctpdBaseTest, BaseIfPropertyTest)
{
    MakeSmbusConfiguration(mctp_server::MctpPhysicalMediumIdentifiers::SmbusI2c,
                           mctp_server::BindingModeTypes::BusOwner, 8,
                           {2, 3, 4, 5, 6}, "");

    /* Set test pass conditions */
    EXPECT_CALL(
        *uuidIntface,
        register_property(StrEq("UUID"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("Eid"), An<uint8_t>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("StaticEid"), An<bool>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("BindingID"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("SocketPath"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("BindingMediumID"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("BindingMode"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *mctpInterface,
        register_property(StrEq("NetworkID"), An<uint8_t>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface,
                register_method(StrEq("SendMctpMessagePayload")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("ReserveBandwidth")))
        .Times(1)
        .WillRepeatedly(Return(true));
    
    EXPECT_CALL(*mctpInterface, register_method(StrEq("SkipList")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("ReleaseBandwidth")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface,
                register_method(StrEq("SendReceiveMctpMessagePayload")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_signal(StrEq("MessageReceivedSignal")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("RegisterResponder")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("SetEIDPool")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("RegisterVdpciResponder")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface,
                register_method(StrEq("TriggerDeviceDiscovery")))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, register_method(StrEq("SendMctpRawPayload")))
        .Times(1)
        .WillRepeatedly(Return(true));
   
    EXPECT_CALL(
        *smbusInterface,
        register_property(StrEq("DiscoveredFlag"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *smbusInterface,
        register_property(StrEq("ArpControllerSupport"), An<bool>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *smbusInterface,
        register_property(StrEq("BusPath"), An<const std::string&>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(
        *smbusInterface,
        register_property(StrEq("BmcTargetAddress"), An<uint8_t>(),
                          Eq(sdbusplus::asio::PropertyPermission::readOnly)))
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*uuidIntface, initialize())
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*mctpInterface, initialize())
        .Times(1)
        .WillRepeatedly(Return(true));

    EXPECT_CALL(*smbusInterface, initialize())
        .Times(1)
        .WillRepeatedly(Return(true));

    boost::asio::io_context ioc;
    auto conn = std::make_shared<sdbusplus::asio::connection>(ioc);

    std::shared_ptr<MctpBinding> bindingPtr = std::make_shared<SMBusBinding>(
        conn, bus, mctpBaseObj, smbusConfig, ioc,
        std::make_shared<boost::asio::posix::stream_descriptor>(ioc));

    bindingPtr->initializeBinding();
}
