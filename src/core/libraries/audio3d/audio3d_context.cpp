// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/logging/log.h"
#include "core/libraries/audio3d/audio3d_context.h"
#include "core/libraries/audio3d/audio3d_error.h"
#include "core/libraries/error_codes.h"

#include <magic_enum.hpp>

namespace Libraries::Audio3d {

Audio3dContext::Audio3dContext() {
    AudioOut::sceAudioOutInit();
}

int Audio3dContext::AudioOutOpen(OrbisAudio3dPortId port_id, OrbisUserServiceUserId user_id,
                                 AudioOut::OrbisAudioOutPort type, s32 index, u32 len, u32 freq,
                                 AudioOut::OrbisAudioOutParamExtendedInformation param) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    auto port = m_ports.at(port_id);

    if (port.parameters.granularity != len) {
        LOG_DEBUG(Lib_Audio3d, "invalid parameter");
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    int ret = AudioOut::sceAudioOutOpen(user_id, type, index, len, freq, param);

    if (ret > AudioOut::SCE_AUDIO_OUT_NUM_PORTS) {
        return ret;
    }

    port.audio_out_handle = ret;
    m_ports[port_id] = port;
    return ret;
}

int Audio3dContext::AudioOutOutput(s32 handle, void* ptr) {
    if (!ptr) {
        LOG_DEBUG(Lib_Audio3d, "invalid parameter");
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    bool found = false;

    for (auto port : m_ports) {
        if (port.second.audio_out_handle != handle) {
            continue;
        }

        found = true;
        CreateQueueObject(port.first, {}, ptr);

        break;
    }

    if (!found) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    return ORBIS_OK;
}

int Audio3dContext::BedWrite2(OrbisAudio3dPortId port_id, u32 num_channels,
                              OrbisAudio3dFormat format, const uintptr_t buffer, u32 num_samples,
                              OrbisAudio3dOutputRoute output_route, bool restricted) {
    LOG_DEBUG(
        Lib_Audio3d,
        "called, port_id = {}, num_channels = {}, format = {}, num_samples = {}, output_route "
        "= {}, restricted = {}",
        port_id, num_channels, magic_enum::enum_name(format), num_samples,
        magic_enum::enum_name(output_route), restricted);

    if (format <= ORBIS_AUDIO3D_FORMAT_FLOAT &&
        ((num_channels | 4) == 6 || (num_channels | 0x10) == 24) && buffer && num_samples) {
        if (format == ORBIS_AUDIO3D_FORMAT_FLOAT) {
            if ((buffer & 3) != 0) {
                return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
            }
        } else if (format == ORBIS_AUDIO3D_FORMAT_S16) {
            if ((buffer & 1) != 0) {
                return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
            }
        }

        if (output_route > ORBIS_AUDIO3D_OUTPUT_BOTH) {
            LOG_DEBUG(Lib_Audio3d, "invalid parameter");
            return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
        }

        if (!ValidatePort(port_id)) {
            LOG_DEBUG(Lib_Audio3d, "invalid port");
            return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
        }

        CreateQueueObject(port_id, {}, reinterpret_cast<void*>(buffer));

        return ORBIS_OK;
    }

    return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
}

int Audio3dContext::ObjectReserve(const OrbisAudio3dPortId port_id, OrbisAudio3dObjectId* id) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    auto& queue = m_queues.at(port_id);
    size_t count = queue.size();

    if (count == m_ports[port_id].parameters.max_objects) {
        LOG_ERROR(Lib_Audio3d, "can't reserve any more objects", port_id);
        return ORBIS_AUDIO3D_ERROR_OUT_OF_RESOURCES;
    }

    *id = count + 1;
    return ORBIS_OK;
}

int Audio3dContext::ObjectSetAttributes(OrbisAudio3dPortId port_id, OrbisAudio3dObjectId object_id,
                                        size_t num_attributes,
                                        const OrbisAudio3dAttribute* attribute_array) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    auto& queue = m_queues[port_id];

    if (num_attributes == 0 || !attribute_array) {
        LOG_DEBUG(Lib_Audio3d, "invalid parameter");
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    std::vector<OrbisAudio3dAttribute> attributes;

    for (size_t i = 0; i < num_attributes; i++) {
        attributes.emplace_back(attribute_array[i]);
    }

    queue.emplace(object_id, attributes, nullptr);

    return ORBIS_OK;
}

int Audio3dContext::PortAdvance(OrbisAudio3dPortId port_id) {
    LOG_DEBUG(Lib_Audio3d, "called");

    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    if (m_ports[port_id].parameters.buffer_mode == ORBIS_AUDIO3D_BUFFER_NO_ADVANCE) {
        LOG_DEBUG(Lib_Audio3d, "no advance");
        return ORBIS_AUDIO3D_ERROR_NOT_SUPPORTED;
    }

    auto& queue = m_queues[port_id];

    if (queue.empty()) {
        LOG_DEBUG(Lib_Audio3d, "no objects, can't advance queue");
        return ORBIS_OK;
    }

    queue.pop();
    return ORBIS_OK;
}

int Audio3dContext::PortClose(OrbisAudio3dPortId port_id) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    m_ports.erase(port_id);
    return ORBIS_OK;
}

int Audio3dContext::PortGetQueueLevel(OrbisAudio3dPortId port_id, u32* queue_level,
                                      u32* queue_available) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    if (!queue_level && !queue_available) {
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    auto size = m_queues[port_id].size();

    if (queue_level) {
        *queue_level = size;
    }

    if (queue_available) {
        u32 available = m_ports[port_id].parameters.queue_depth - m_queues[port_id].size();
        *queue_available = available;
    }

    return ORBIS_OK;
}

int Audio3dContext::PortOpen(OrbisUserServiceUserId user_id,
                             const OrbisAudio3dOpenParameters* parameters, OrbisAudio3dPortId* id) {
    if (!parameters || parameters->buffer_mode > ORBIS_AUDIO3D_BUFFER_ADVANCE_AND_PUSH ||
        parameters->num_beds != 2 || !parameters->queue_depth || !parameters->max_objects ||
        parameters->granularity < 0x100) {
        LOG_DEBUG(Lib_Audio3d, "invalid parameters");
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    // Create a copy to avoid dangling references
    auto parameters_copy = *parameters;

    *id = m_ports.size();
    m_ports.emplace(*id, Port{parameters_copy, std::nullopt});
    m_queues[*id] = {};
    return ORBIS_OK;
}

int Audio3dContext::PortPush(OrbisAudio3dPortId port_id, OrbisAudio3dBlocking blocking) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    auto port = m_ports[port_id];

    if (port.parameters.buffer_mode != ORBIS_AUDIO3D_BUFFER_ADVANCE_AND_PUSH) {
        LOG_DEBUG(Lib_Audio3d, "not supported");
        return ORBIS_AUDIO3D_ERROR_NOT_SUPPORTED;
    }

    auto& queue = m_queues[port_id];

    if (queue.empty()) {
        LOG_DEBUG(Lib_Audio3d, "no objects, can't push");
        return ORBIS_OK;
    }

    auto queue_object = queue.front();

    if (queue_object.pcm) {
        LOG_DEBUG(Lib_Audio3d, "pcm");
        AudioOut::sceAudioOutOutput(port.audio_out_handle.value(), queue_object.pcm);
    } else if (queue_object.attributes.has_value()) {
        for (auto attribute : queue_object.attributes.value()) {
            if (attribute.attribute_id != 0x1) { // PCM
                continue;
            }

            AudioOut::sceAudioOutOutput(1, attribute.value);
        }
    }

    queue.pop();
    return ORBIS_OK;
}

u32 Audio3dContext::CreateQueueObject(u32 port_id,
                                      const std::vector<OrbisAudio3dAttribute>& attributes,
                                      void* pcm) {
    if (!ValidatePort(port_id)) {
        LOG_DEBUG(Lib_Audio3d, "invalid port");
        return ORBIS_AUDIO3D_ERROR_INVALID_PORT;
    }

    auto& queue = m_queues[port_id];

    if (pcm) {
        LOG_DEBUG(Lib_Audio3d, "pcm");
        queue.emplace(std::nullopt, std::nullopt, pcm);
        return ORBIS_OK;
    }

    LOG_DEBUG(Lib_Audio3d, "no pcm");
    u32 id = queue.size() + 1;
    queue.emplace(id, attributes, nullptr);
    return id;
}

} // namespace Libraries::Audio3d
