// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/assert.h"
#include "common/logging/log.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/network/net_client.h"
#include "core/libraries/network/net_error.h"

namespace Libraries::Net {

Client::Client() : m_io_context(boost::asio::io_context()) {}

OrbisNetId Client::Socket(const char* name, int family, SocketType type, int protocol) {
    LOG_INFO(Lib_Net, "called, name = {}, family = {}, type = {}, protocol = {}", name, family,
             magic_enum::enum_name(type), protocol);

    u32 id = m_sockets.size() + 1;

    if (type == ORBIS_NET_SOCK_STREAM_P2P || type == ORBIS_NET_SOCK_STREAM) {
        m_sockets.emplace(id, TcpSocket{type, boost::asio::ip::tcp::socket(
                                                  m_io_context, boost::asio::ip::tcp::v4())});
    } else if (type == ORBIS_NET_SOCK_DGRAM || type == ORBIS_NET_SOCK_DGRAM_P2P) {
        m_sockets.emplace(id, UdpSocket{type, boost::asio::ip::udp::socket(
                                                  m_io_context, boost::asio::ip::udp::v4())});
    } else {
        UNREACHABLE_MSG("unsupported socket type {}", magic_enum::enum_name(type));
    }

    LOG_INFO(Lib_Net, "created socket {}", id);
    return id;
}

int Client::GetMacAddress(OrbisNetEtherAddr* addr, int flag) {
    LOG_INFO(Lib_Net, "called, addr = {}, flag = {}", reinterpret_cast<void*>(addr), flag);

    if (!addr || flag != 0) {
        LOG_ERROR(Lib_Net, "invalid arguments");
        net_errno = EINVAL;
        return ORBIS_NET_ERROR_EINVAL;
    }

    // Fuck you, 11:22:33:44:55:66
    std::memcpy(addr->data, "\x11\x22\x33\x44\x55\x66", ORBIS_NET_ETHER_ADDR_LEN);
    return ORBIS_OK;
}

int Client::SendTo(OrbisNetId s, void* buf, size_t len, int flags, const OrbisNetSockaddr* addr,
                   OrbisNetSocklen_t addrlen) {
    LOG_INFO(Lib_Net, "called, s = {}, buf = {}, len = {}, flags = {}, addr = {}, addrlen = {}", s,
             buf, len, flags, reinterpret_cast<const void*>(addr), addrlen);

    if (!buf || !addr) {
        LOG_ERROR(Lib_Net, "invalid arguments");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    if (!IsSocketValid(s)) {
        LOG_ERROR(Lib_Net, "invalid socket id");
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    auto socket = m_sockets.find(s);
    auto in = std::string(static_cast<char*>(buf), len);

    try {
        if (std::holds_alternative<UdpSocket>(socket->second)) {
            auto& udp_socket = std::get<UdpSocket>(socket->second);
            boost::asio::ip::udp::resolver resolver(m_io_context);
            boost::asio::ip::udp::endpoint receiver_endpoint =
                *resolver.resolve(boost::asio::ip::udp::v4(), "127.0.0.1", "18958").begin();

            auto sent = udp_socket.socket.send_to(boost::asio::buffer(in), receiver_endpoint);
            LOG_INFO(Lib_Net, "sent {} bytes", sent);
        } else {
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("failed to send data through socket {}: {}", s, e.what());
    }

    return ORBIS_FAIL;
}

int Client::Bind(OrbisNetId s, const OrbisNetSockaddr* address, OrbisNetSocklen_t address_len) {
    LOG_INFO(Lib_Net, "called, socket = {}, address = {}, address_len = {}", s,
             reinterpret_cast<const void*>(address), address_len);

    if (!address || address_len == 0) {
        LOG_ERROR(Lib_Net, "invalid parameter");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    if (!IsSocketValid(s)) {
        LOG_ERROR(Lib_Net, "invalid socket id");
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    auto socket = m_sockets.find(s);
    const auto* addr = reinterpret_cast<const OrbisNetSockaddrIn*>(address);

    if (addr->sin_family != AF_INET) {
        UNREACHABLE_MSG("unsupported address family {}", address->sa_family);
    }

    try {
        std::string url = boost::asio::ip::address_v4(addr->sin_addr.s_addr_).to_string();

        if (url == "0.0.0.0") {
            LOG_INFO(Lib_Net, "binding to any address");
        } else {
            LOG_INFO(Lib_Net, "binding to address {}", url);
        }

        LOG_INFO(Lib_Net, "binding to port {}", addr->sin_port);

        if (std::holds_alternative<UdpSocket>(socket->second)) {
            auto& udp_socket = std::get<UdpSocket>(socket->second);

            boost::asio::ip::udp::resolver resolver(m_io_context);
            boost::asio::ip::udp::endpoint receiver_endpoint =
                *resolver.resolve(boost::asio::ip::udp::v4(), url, std::to_string(addr->sin_port))
                     .begin();

            udp_socket.socket.bind(receiver_endpoint);
        } else {
            auto& tcp_socket = std::get<TcpSocket>(socket->second);

            boost::asio::ip::tcp::resolver resolver(m_io_context);
            boost::asio::ip::tcp::endpoint receiver_endpoint =
                *resolver.resolve(url, std::to_string(addr->sin_port)).begin();

            tcp_socket.socket.bind(receiver_endpoint);
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("failed to bind socket {}: {}", s, e.what());
    }

    return ORBIS_OK;
}

bool Client::IsSocketValid(OrbisNetId s) const {
    return m_sockets.find(s) != m_sockets.end();
}

int Client::SocketClose(OrbisNetId s) {
    LOG_INFO(Lib_Net, "called, socket = {}", s);

    if (!IsSocketValid(s)) {
        LOG_ERROR(Lib_Net, "invalid socket id");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    auto socket = m_sockets.find(s);

    try {
        if (std::holds_alternative<UdpSocket>(socket->second)) {
            auto& udp_socket = std::get<UdpSocket>(socket->second);
            udp_socket.socket.close();
        } else {
            auto& tcp_socket = std::get<TcpSocket>(socket->second);
            tcp_socket.socket.close();
        }
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("failed to close socket {}: {}", s, e.what());
    }

    m_sockets.erase(s);
    return ORBIS_OK;
}

// Get socket for which TCP connection was established
int Client::Listen(OrbisNetId s, int backlog) {
    LOG_INFO(Lib_Net, "called, socket = {}, backlog = {}", s, backlog);

    if (!IsSocketValid(s)) {
        LOG_ERROR(Lib_Net, "invalid socket id");
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    auto socket = m_sockets.find(s);

    if (std::holds_alternative<UdpSocket>(socket->second)) {
        LOG_ERROR(Lib_Net, "socket is not a TCP socket");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    auto& tcp_socket = std::get<TcpSocket>(socket->second);

    try {
        m_acceptor = std::make_unique<boost::asio::ip::tcp::acceptor>(
            m_io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 9025));
        m_acceptor->listen(backlog);
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("failed to listen on socket {}: {}", s, e.what());
    }

    return ORBIS_OK;
}

OrbisNetId Client::Accept(OrbisNetId s, OrbisNetSockaddr* address, OrbisNetSocklen_t* address_len) {
    LOG_INFO(Lib_Net, "called, socket = {}, address = {}, address_len = {}", s,
             reinterpret_cast<void*>(address), reinterpret_cast<void*>(address_len));

    if (!address || !address_len) {
        LOG_ERROR(Lib_Net, "invalid arguments");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    if (!IsSocketValid(s)) {
        LOG_ERROR(Lib_Net, "invalid socket id");
        net_errno = EBADF;
        return ORBIS_FAIL;
    }

    auto socket = m_sockets.find(s);

    if (std::holds_alternative<UdpSocket>(socket->second)) {
        LOG_ERROR(Lib_Net, "socket is not a TCP socket");
        net_errno = EINVAL;
        return ORBIS_FAIL;
    }

    auto& tcp_socket = std::get<TcpSocket>(socket->second);

    try {
        boost::asio::ip::tcp::socket new_socket(m_io_context);
        m_acceptor->accept(new_socket);

        auto id = m_sockets.size() + 1;
        m_sockets.emplace(id, TcpSocket{ORBIS_NET_SOCK_STREAM, std::move(new_socket)});

        return id;
    } catch (const boost::system::system_error& e) {
        UNREACHABLE_MSG("failed to accept connection on socket {}: {}", s, e.what());
    }
}

} // namespace Libraries::Net
