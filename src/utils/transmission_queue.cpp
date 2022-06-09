#include "utils/transmission_queue.hpp"

#include <phosphor-logging/log.hpp>

#include "libmctp-cmds.h"

using mctpd::MctpTransmissionQueue;

MctpTransmissionQueue::Message::Message(size_t index_,
                                        std::vector<uint8_t>&& payload_,
                                        std::vector<uint8_t>&& privateData_,
                                        boost::asio::io_context& ioc) :
    index(index_),
    payload(std::move(payload_)), privateData(std::move(privateData_)),
    timer(ioc)
{
}

std::optional<uint8_t> MctpTransmissionQueue::Tags::next() const
{
    if (!bits)
    {
        return std::nullopt;
    }
    return static_cast<uint8_t>(__builtin_ctz(bits));
}

void MctpTransmissionQueue::Tags::emplace(uint8_t flag)
{
    bits |= static_cast<uint8_t>(1 << flag);
}

void MctpTransmissionQueue::Tags::erase(uint8_t flag)
{
    bits &= static_cast<uint8_t>(~(1 << flag));
}

std::shared_ptr<MctpTransmissionQueue::Message> MctpTransmissionQueue::transmit(
    struct mctp* mctp, mctp_eid_t destEid, std::vector<uint8_t>&& payload,
    std::vector<uint8_t>&& privateData, boost::asio::io_context& ioc)
{
    auto& endpoint = endpoints[destEid];
    auto msgIndex = endpoint.msgCounter++;
    auto message = std::make_shared<Message>(msgIndex, std::move(payload),
                                             std::move(privateData), ioc);
    endpoint.queuedMessages.emplace(msgIndex, message);
    endpoint.transmitQueuedMessages(mctp, destEid);
    return message;
}

void MctpTransmissionQueue::Endpoint::transmitQueuedMessages(struct mctp* mctp,
                                                             mctp_eid_t destEid)
{
    while (!queuedMessages.empty())
    {
        const std::optional<uint8_t> nextTag = availableTags.next();
        if (!nextTag)
        {
            break;
        }
        auto msgTag = nextTag.value();
        auto queuedMessageIter = queuedMessages.begin();
        auto message = std::move(queuedMessageIter->second);
        queuedMessages.erase(queuedMessageIter);

        int rc = mctp_message_tx(mctp, destEid, message->payload.data(),
                                 message->payload.size(), true, msgTag,
                                 message->privateData.data());
        if (rc < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error in mctp_message_tx");
            continue;
        }

        availableTags.erase(msgTag);
        message->tag = msgTag;
        transmittedMessages.emplace(msgTag, std::move(message));
    }
}

static uint8_t getInstanceId(const uint8_t msg)
{
    return msg & MCTP_CTRL_HDR_INSTANCE_ID_MASK;
}

bool MctpTransmissionQueue::Message::checkMatchingControlCmdRequest(
    std::vector<uint8_t>& resp) const
{
    constexpr size_t mctpControlMessageHeaderSize = sizeof(mctp_ctrl_msg_hdr);
    if (payload.size() < mctpControlMessageHeaderSize ||
        resp.size() < mctpControlMessageHeaderSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Request message size too small");
        return false;
    }

    const mctp_ctrl_msg_hdr* reqHeader =
        reinterpret_cast<const mctp_ctrl_msg_hdr*>(payload.data());
    const mctp_ctrl_msg_hdr* respHeader =
        reinterpret_cast<const mctp_ctrl_msg_hdr*>(resp.data());
    if (getInstanceId(reqHeader->rq_dgram_inst) ==
        getInstanceId(respHeader->rq_dgram_inst))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Matching MCTP Control command request found!!");
        return true;
    }
    return false;
}

bool MctpTransmissionQueue::Endpoint::checkMatchingControlCmdRequest(
    uint8_t msgTag, std::vector<uint8_t>& response) const
{
    auto messageIter = transmittedMessages.find(msgTag);
    if (messageIter == transmittedMessages.end())
    {
        return false;
    }

    const auto& message = messageIter->second;
    if (message->checkMatchingControlCmdRequest(response))
    {
        return true;
    }
    return false;
}

std::optional<mctp_eid_t> MctpTransmissionQueue::checkMatchingControlCmdRequest(
    uint8_t msgTag, std::vector<uint8_t>& response)
{

    for (auto const& [eid, endpoint] : endpoints)
    {
        if (endpoint.checkMatchingControlCmdRequest(msgTag, response))
        {
            return eid;
        }
    }
    return std::nullopt;
}

static bool isMCTPControlResponse(std::vector<uint8_t>& response)
{
    if (mctp_is_mctp_ctrl_msg(response.data(), response.size()) &&
        !mctp_ctrl_msg_is_req(response.data(), response.size()))
    {
        return true;
    }
    return false;
}

bool MctpTransmissionQueue::receive(struct mctp* mctp, mctp_eid_t srcEid,
                                    uint8_t msgTag,
                                    std::vector<uint8_t>&& response,
                                    boost::asio::io_context& ioc)
{
    // (Message tag) Field that, along with the Source Endpoint IDs and the Tag
    // Owner (TO) field, identifies a unique message at the MCTP transport
    // level. It is not mandatory that 'srcEid' reported in MCTP control command
    // responses should match with the EID we used to send. It can differ in
    // cases like device lost it's EID due to reset. Thus extract last known EID
    // from 'transmittedMessages' based on Instance ID, Message Tag. Also, give
    // preference to MCTP Control message check over other messages.
    if (isMCTPControlResponse(response))
    {
        if (auto eid = checkMatchingControlCmdRequest(msgTag, response))
        {
            srcEid = eid.value();
        }
    }

    auto endpointIter = endpoints.find(srcEid);
    if (endpointIter == endpoints.end())
    {
        return false;
    }

    auto& endpoint = endpointIter->second;
    auto messageIter = endpoint.transmittedMessages.find(msgTag);
    if (messageIter == endpoint.transmittedMessages.end())
    {
        return false;
    }

    const auto message = messageIter->second;
    message->response = std::move(response);
    endpoint.transmittedMessages.erase(messageIter);
    message->tag.reset();
    endpoint.availableTags.emplace(msgTag);

    // Now that another tag is available, try to transmit any queued messages
    message->timer.cancel();
    ioc.post([this, mctp, srcEid] {
        endpoints[srcEid].transmitQueuedMessages(mctp, srcEid);
    });
    return true;
}

void MctpTransmissionQueue::dispose(mctp_eid_t destEid,
                                    const std::shared_ptr<Message>& message)
{
    auto& endpoint = endpoints[destEid];
    auto queuedMessageIter = endpoint.queuedMessages.find(message->index);
    if (queuedMessageIter != endpoint.queuedMessages.end())
    {
        endpoint.queuedMessages.erase(queuedMessageIter);
    }
    if (message->tag)
    {
        auto msgTag = message->tag.value();
        endpoint.availableTags.emplace(msgTag);

        auto transmittedMessageIter = endpoint.transmittedMessages.find(msgTag);
        if (transmittedMessageIter != endpoint.transmittedMessages.end())
        {
            endpoint.transmittedMessages.erase(transmittedMessageIter);
        }
    }
}