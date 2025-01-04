// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <memory>
#include <boost/asio.hpp>

namespace Libraries::Kernel {

/// Wraps some Asio code, not really needed but I think it helps with readability in NetHandler
template <typename Type>
class NetConnection {
public:
    using Socket = Type::socket;

    explicit NetConnection(boost::asio::io_context& io_context, int protocol)
        : m_io_context(io_context), m_socket(std::make_unique<Socket>(m_io_context, protocol)){};

    /* Connectivity */
    void Bind(const std::string& address, u16 port) {
        typename Type::endpoint endpoint(boost::asio::ip::make_address(address), port);
        boost::system::error_code ec;
        m_socket->bind(endpoint, ec);
        ASSERT_MSG(!ec, "Failed to bind socket: {}", ec.message());
    };

    [[nodiscard]] Socket& GetSocket() {
        return *m_socket;
    };

private:
    boost::asio::io_context& m_io_context;
    std::unique_ptr<Socket> m_socket;
};

} // namespace Libraries::Kernel
