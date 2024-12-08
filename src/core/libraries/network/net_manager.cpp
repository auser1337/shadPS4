// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <magic_enum.hpp>
#include "common/assert.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/network/net_manager.h"
#include "net_error.h"

using namespace boost::asio;

namespace Libraries::Net {

NetManager::NetManager() : m_tcp_resolver(m_io_context), m_udp_resolver(m_io_context) {}

// TODO: Take in protocols for below 2 functions

OrbisNetId NetManager::CreateTcpSocket(const SocketType type) {
    const OrbisNetId id = static_cast<OrbisNetId>(m_sockets.size()) + 1;
    m_sockets[id] = Socket{type, std::make_shared<ip::tcp::socket>(m_io_context, ip::tcp::v4())};
    return id;
}

OrbisNetId NetManager::CreateUdpSocket(const SocketType type) {
    const OrbisNetId id = static_cast<OrbisNetId>(m_sockets.size()) + 1;
    m_sockets[id] = Socket{type, std::make_shared<ip::udp::socket>(m_io_context, ip::udp::v4())};
    return id;
}

int NetManager::CloseSocket(const OrbisNetId s) {
    const auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    const auto asio_socket = it->second.asio_socket;

    try {
        if (const auto tcp_socket_ptr =
                std::get_if<std::shared_ptr<ip::tcp::socket>>(&asio_socket)) {
            tcp_socket_ptr->get()->close();
        } else if (const auto udp_socket_ptr =
                       std::get_if<std::shared_ptr<ip::udp::socket>>(&asio_socket)) {
            udp_socket_ptr->get()->close();
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("Failed to close socket {}, {}", s, e.what());
    }

    m_sockets.erase(s);
    return ORBIS_OK;
}

int NetManager::Bind(const OrbisNetId s, const std::string& address, const u16 port) {
    LOG_INFO(Lib_Net, "Binding socket {} to {}:{}", s, address, port);

    const auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    const auto asio_socket = it->second.asio_socket;

    if (const auto tcp_socket_ptr = std::get_if<std::shared_ptr<ip::tcp::socket>>(&asio_socket)) {
        const auto tcp_socket = *tcp_socket_ptr;
        tcp_socket->bind(ResolveTcpEndpoint(address, port));
    } else if (const auto udp_socket_ptr =
                   std::get_if<std::shared_ptr<ip::udp::socket>>(&asio_socket)) {
        const auto udp_socket = *udp_socket_ptr;
        udp_socket->bind(ResolveUdpEndpoint(address, port));
    }

    return ORBIS_OK;
}

int NetManager::Send(OrbisNetId s, mutable_buffer buffer, const int flags) {
    const auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    if (flags & ORBIS_NET_MSG_USECRYPTO) {
        UNIMPLEMENTED_MSG("Crypto not implemented");
    }

    const auto asio_socket = it->second.asio_socket;

    auto send_data = [&](auto& socket) {
        if (flags & ORBIS_NET_MSG_DONTWAIT) {
            socket->async_send(buffer, [s](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    LOG_ERROR(Lib_Net, "Failed to send data on socket {}: {}", s, ec.message());
                }
            });
        } else {
            socket->send(buffer);
        }
    };

    if (const auto tcp_socket_ptr = std::get_if<std::shared_ptr<ip::tcp::socket>>(&asio_socket)) {
        send_data(*tcp_socket_ptr);
    } else if (const auto udp_socket_ptr =
                   std::get_if<std::shared_ptr<ip::udp::socket>>(&asio_socket)) {
        send_data(*udp_socket_ptr);
    }

    return ORBIS_OK;
}

int NetManager::SendTo(const OrbisNetId s, const mutable_buffer buffer, const std::string& address,
                       const u16 port, const int flags) {
    const auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    if (flags & ORBIS_NET_MSG_USECRYPTO) {
        UNIMPLEMENTED_MSG("Crypto not implemented");
    }

    const auto udp_socket = *std::get_if<std::shared_ptr<ip::udp::socket>>(&it->second.asio_socket);

    if (!udp_socket) {
        net_errno = EPROTOTYPE;
        return ORBIS_FAIL;
    }

    if (flags & ORBIS_NET_MSG_DONTWAIT) {
        udp_socket->async_send_to(
            buffer, ip::udp::endpoint(ip::address::from_string(address), port),
            [&](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    LOG_ERROR(Lib_Net, "Failed to send data on socket {} to {}:{}, {}", s, address,
                              port, ec.message());
                }
            });
    } else {
        udp_socket->send_to(buffer, ip::udp::endpoint(ip::address::from_string(address), port));
    }

    return ORBIS_OK;
}

ip::tcp::endpoint NetManager::ResolveTcpEndpoint(const std::string& address, const u16 port) {
    const auto results =
        m_tcp_resolver.resolve(ip::make_address_v4(address).to_string(), std::to_string(port));
    if (results.empty()) {
        throw std::runtime_error("Failed to resolve address: " + address);
    }
    return *results.begin();
}

ip::udp::endpoint NetManager::ResolveUdpEndpoint(const std::string& address, const u16 port) {
    const auto results = m_udp_resolver.resolve(
        ip::udp::v4(), ip::make_address_v4(address).to_string(), std::to_string(port));
    if (results.empty()) {
        throw std::runtime_error("Failed to resolve address: " + address);
    }
    return *results.begin();
}

} // namespace Libraries::Net
