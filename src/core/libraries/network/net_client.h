// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "core/libraries/network/net.h"

#include <variant>
#include <boost/asio.hpp>
#include <boost/container/map.hpp>
#include <magic_enum.hpp>

namespace Libraries::Net {

// TODO: This is also used for server functions, rename it?
class Client {
public:
    Client();

    static int GetMacAddress(OrbisNetEtherAddr* addr, int flag);
    int SendTo(OrbisNetId s, void* buf, size_t len, int flags, const OrbisNetSockaddr* addr,
               OrbisNetSocklen_t addrlen);
    OrbisNetId Socket(const char* name, int family, SocketType type, int protocol);
    int SocketClose(OrbisNetId s);
    int Bind(OrbisNetId s, const OrbisNetSockaddr* address, OrbisNetSocklen_t address_len);
    int Listen(OrbisNetId s, int backlog);
    OrbisNetId Accept(OrbisNetId s, OrbisNetSockaddr* address, OrbisNetSocklen_t* address_len);

private:
    struct TcpSocket {
        SocketType type;
        boost::asio::ip::tcp::socket socket;
    };

    struct UdpSocket {
        SocketType type;
        boost::asio::ip::udp::socket socket;
    };

    boost::asio::io_context m_io_context;
    boost::container::map<OrbisNetId, std::variant<TcpSocket, UdpSocket>> m_sockets;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;

    [[nodiscard]] bool IsSocketValid(OrbisNetId socket) const;
};

} // namespace Libraries::Net
