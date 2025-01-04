// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <unordered_map>
#include <variant>
#include <boost/asio.hpp>

namespace Libraries::Kernel {

class NetHandler {
public:
    explicit NetHandler() = default;
    ~NetHandler() = default;

    int CreateSocket(int domain, int type, int protocol);
    int Bind(int s, const sockaddr* addr, socklen_t addrlen);
    int Listen(int s, int backlog);
    int Connect(int s, const sockaddr* name, socklen_t namelen);

private:
    using Connection =
        std::variant<NetConnection<boost::asio::ip::tcp>, NetConnection<boost::asio::ip::udp>>;

    boost::asio::io_context m_io_context;
    std::unordered_map<int, Connection> m_connections;
};

} // namespace Libraries::Kernel
