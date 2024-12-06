// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <magic_enum.hpp>
#include "common/assert.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/network/net_manager.h"
#include "net_error.h"

namespace Libraries::Net {

NetManager::NetManager()
    : m_io_context(), m_tcp_resolver(m_io_context), m_udp_resolver(m_io_context) {}

// TODO: Take in protocols for below 2 functions

OrbisNetId NetManager::CreateTcpSocket(SocketType type) {
    OrbisNetId id = static_cast<OrbisNetId>(m_sockets.size()) + 1;
    m_sockets[id] = Socket{type, std::make_shared<boost::asio::ip::tcp::socket>(
                                     m_io_context, boost::asio::ip::tcp::v4())};
    return id;
}

OrbisNetId NetManager::CreateUdpSocket(SocketType type) {
    OrbisNetId id = static_cast<OrbisNetId>(m_sockets.size()) + 1;
    m_sockets[id] = Socket{type, std::make_shared<boost::asio::ip::udp::socket>(
                                     m_io_context, boost::asio::ip::udp::v4())};
    return id;
}

int NetManager::CloseSocket(OrbisNetId s) {
    auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        FailAndSetErrno(EBADF);
    }

    auto internal_socket = it->second.internal_socket;

    try {
        if (std::holds_alternative<std::shared_ptr<boost::asio::ip::tcp::socket>>(
                internal_socket)) {
            auto& tcp_socket =
                std::get<std::shared_ptr<boost::asio::ip::tcp::socket>>(internal_socket);
            tcp_socket->close();
        } else {
            auto& udp_socket =
                std::get<std::shared_ptr<boost::asio::ip::udp::socket>>(internal_socket);
            udp_socket->close();
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("Failed to close socket {}, {}", s, e.what());
    }

    m_sockets.erase(s);
    return ORBIS_OK;
}

int NetManager::Bind(OrbisNetId s, const std::string& address, u16 port) {
    LOG_INFO(Lib_Net, "Binding socket {} to {}:{}", s, address, port);

    auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        FailAndSetErrno(EBADF);
    }

    auto internal_socket = it->second.internal_socket;

    try {
        if (std::holds_alternative<std::shared_ptr<boost::asio::ip::tcp::socket>>(
                internal_socket)) {
            auto& tcp_socket =
                std::get<std::shared_ptr<boost::asio::ip::tcp::socket>>(internal_socket);
            // disgusting
            auto endpoint = *m_tcp_resolver
                                 .resolve(boost::asio::ip::make_address_v4(address).to_string(),
                                          std::to_string(port))
                                 .begin();
            tcp_socket->bind(endpoint);
        } else {
            auto& udp_socket =
                std::get<std::shared_ptr<boost::asio::ip::udp::socket>>(internal_socket);
            // disgustingest
            auto endpoint = *m_udp_resolver
                                 .resolve(boost::asio::ip::udp::v4(),
                                          boost::asio::ip::make_address_v4(address).to_string(),
                                          std::to_string(port))
                                 .begin();
            udp_socket->bind(endpoint);
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("Failed to bind socket {}, {}", s, e.what());
    }

    return ORBIS_OK;
}

int NetManager::Send(OrbisNetId s, boost::asio::mutable_buffer buffer, int flags) {
    auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        return FailAndSetErrno(EBADF);
    }

    if (flags & ORBIS_NET_MSG_USECRYPTO) {
        UNIMPLEMENTED_MSG("Crypto not implemented");
    }

    auto internal_socket = it->second.internal_socket;

    try {
        auto send_data = [&](auto& socket) {
            if (flags & ORBIS_NET_MSG_DONTWAIT) {
                socket->async_send(buffer, [s](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        LOG_ERROR(Lib_Net, "Failed to send data on socket {}: {}", s, ec.message());
                    }
                });
                return;
            }

            socket->send(buffer);
        };

        if (std::holds_alternative<std::shared_ptr<boost::asio::ip::tcp::socket>>(
                internal_socket)) {
            auto& tcp_socket =
                std::get<std::shared_ptr<boost::asio::ip::tcp::socket>>(internal_socket);
            send_data(tcp_socket);
        } else {
            auto& udp_socket =
                std::get<std::shared_ptr<boost::asio::ip::udp::socket>>(internal_socket);
            send_data(udp_socket);
        }
    } catch (const boost::system::system_error& e) {
        LOG_ERROR(Lib_Net, "Failed to send data on socket {}, {}", s, e.what());
        return ORBIS_FAIL;
    }

    return ORBIS_OK;
}

int NetManager::SendTo(OrbisNetId s, boost::asio::mutable_buffer buffer, const std::string& address,
                       u16 port, int flags) {
    auto it = m_sockets.find(s);
    if (it == m_sockets.end()) {
        return FailAndSetErrno(EBADF);
    }

    if (flags & ORBIS_NET_MSG_USECRYPTO) {
        UNIMPLEMENTED_MSG("Crypto not implemented");
    }

    auto internal_socket = it->second.internal_socket;

    ASSERT_MSG(
        std::holds_alternative<std::shared_ptr<boost::asio::ip::udp::socket>>(internal_socket),
        "Socket must be UDP");

    try {
        auto& udp_socket = std::get<std::shared_ptr<boost::asio::ip::udp::socket>>(internal_socket);

        if (flags & ORBIS_NET_MSG_DONTWAIT) {
            udp_socket->async_send_to(
                buffer,
                boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(address),
                                               port),
                [&](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        LOG_ERROR(Lib_Net, "Failed to send data on socket {} to {}:{}, {}", s,
                                  address, port, ec.message());
                    }
                });
            return ORBIS_OK;
        }

        udp_socket->send_to(buffer, boost::asio::ip::udp::endpoint(
                                        boost::asio::ip::address::from_string(address), port));
    } catch (const boost::system::system_error& e) {
        LOG_ERROR(Lib_Net, "Failed to send data on socket {}, {}", s, e.what());
        return ORBIS_FAIL;
    }

    return ORBIS_OK;
}

int NetManager::FailAndSetErrno(int err) {
    LOG_ERROR(Lib_Net, "errno: {}", err);
    net_errno = err;
    return ORBIS_FAIL;
}

} // namespace Libraries::Net
