// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/assert.h"
#include "core/libraries/kernel/net_connection.h"
#include "core/libraries/kernel/posix_net.h"

#include <boost/asio/detail/socket_types.hpp>

using namespace boost::asio::ip;

namespace Libraries::Kernel {

// Wow, what a terrible name
static std::pair<std::string, u16> SockaddrToStringAndPort(const sockaddr* sockaddr) {
    char buffer[INET6_ADDRSTRLEN]{};

    switch (sockaddr->sa_family) {
    case AF_INET:
        ASSERT(inet_ntop(AF_INET, &(((struct sockaddr_in*)sockaddr)->sin_addr), buffer,
                         sizeof(buffer)));
        break;
    case AF_INET6:
        ASSERT(inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sockaddr)->sin6_addr), buffer,
                         sizeof(buffer)));
        break;
    default:
        UNREACHABLE();
    }

    return {buffer, htons(((struct sockaddr_in*)sockaddr)->sin_port)};
}

int NetHandler::CreateSocket(int domain, int type, int protocol) {
    int id = static_cast<int>(m_connections.size());

    switch (type) {
    case SOCK_STREAM:
        m_connections.emplace(id, NetConnection<tcp>(m_io_context, protocol));
        break;
    case SOCK_DGRAM:
        m_connections.emplace(id, NetConnection<udp>(m_io_context, protocol));
        break;
    default:
        UNIMPLEMENTED_MSG("Socket type {}", type);
    }

    return id;
}

int NetHandler::Bind(int s, const struct sockaddr* addr, socklen_t addrlen) {
    auto connection = m_connections.find(s);

    if (connection == m_connections.end()) {
        return EBADF;
    }

    std::visit(
        [addr](auto& conn) {
            auto [ip, port] = SockaddrToStringAndPort(addr);
            conn.Bind(ip, port);
        },
        connection->second);

    return 0;
}

int NetHandler::Listen(int s, int backlog) {
    return 0;
}

int NetHandler::Connect(int s, const sockaddr* name, socklen_t namelen) {
    return 0;
}

} // namespace Libraries::Kernel
