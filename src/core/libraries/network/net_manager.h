// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "net.h"

#include <unordered_map>
#include <variant>
#include <boost/asio.hpp>

namespace Libraries::Net {

class NetManager {
public:
    NetManager();

    /* Socket I/O */
    // TODO: Merge CreateTcpSocket and CreateUdpSocket
    OrbisNetId CreateTcpSocket(SocketType type);
    OrbisNetId CreateUdpSocket(SocketType type);
    int CloseSocket(OrbisNetId s);

    /* Socket connection */
    int Bind(OrbisNetId s, const std::string& address, u16 port);

    /* Socket communication */
    int Send(OrbisNetId s, boost::asio::mutable_buffer buffer, int flags = 0);
    int SendTo(OrbisNetId s, boost::asio::mutable_buffer buffer, const std::string& address,
               u16 port, int flags = 0);

private:
    struct Socket {
        using TcpSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;
        using UdpSocketPtr = std::shared_ptr<boost::asio::ip::udp::socket>;

        SocketType type;
        std::variant<TcpSocketPtr, UdpSocketPtr> internal_socket;
    };

    boost::asio::io_context m_io_context;
    std::unordered_map<OrbisNetId, Socket> m_sockets;
    boost::asio::ip::tcp::resolver m_tcp_resolver;
    boost::asio::ip::udp::resolver m_udp_resolver;

    static inline int FailAndSetErrno(int err); // Do I really need this?
};

} // namespace Libraries::Net
