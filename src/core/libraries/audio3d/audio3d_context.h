// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/libraries/audio/audioout.h"
#include "core/libraries/audio3d/audio3d.h"

#include <optional>
#include <unordered_map>
#include <queue>

namespace Libraries::Audio3d {

class Audio3dContext {
public:
    Audio3dContext();
    ~Audio3dContext() = default;

    int AudioOutOpen(OrbisAudio3dPortId port_id, OrbisUserServiceUserId user_id,
                     AudioOut::OrbisAudioOutPort type, s32 index, u32 len, u32 freq,
                     AudioOut::OrbisAudioOutParamExtendedInformation param);
    int AudioOutOutput(s32 handle, void* ptr);
    int BedWrite2(OrbisAudio3dPortId port_id, u32 num_channels, OrbisAudio3dFormat format,
                  uintptr_t buffer, u32 num_samples, OrbisAudio3dOutputRoute output_route,
                  bool restricted);
    int ObjectReserve(OrbisAudio3dPortId port_id, OrbisAudio3dObjectId* id);
    int ObjectSetAttributes(OrbisAudio3dPortId port_id, OrbisAudio3dObjectId object_id,
                            size_t num_attributes, const OrbisAudio3dAttribute* attribute_array);
    int PortAdvance(OrbisAudio3dPortId port_id);
    int PortClose(OrbisAudio3dPortId port_id);
    int PortGetQueueLevel(OrbisAudio3dPortId port_id, u32* queue_level, u32* queue_available);
    int PortOpen(OrbisUserServiceUserId user_id, const OrbisAudio3dOpenParameters* parameters,
                 OrbisAudio3dPortId* id);
    int PortPush(OrbisAudio3dPortId port_id, OrbisAudio3dBlocking blocking);

private:
    struct Port {
        OrbisAudio3dOpenParameters parameters{};
        std::optional<s32> audio_out_handle;
    };

    struct QueueObject {
        // TODO: There might be a better way to handle this
        std::optional<OrbisAudio3dObjectId> object_id;
        std::optional<std::vector<OrbisAudio3dAttribute>> attributes;
        void* pcm{};
    };

    std::unordered_map<u32, Port> m_ports;
    std::unordered_map<u32, std::queue<QueueObject>> m_queues;

    [[nodiscard]] bool ValidatePort(OrbisAudio3dPortId port_id) const {
        return m_ports.find(port_id) != m_ports.end();
    };
    [[nodiscard]] bool ValidateQueueObject(OrbisAudio3dPortId port_id, u32 object_id) const {
        return m_queues.at(port_id).size() > object_id;
    };

    u32 CreateQueueObject(u32 port_id, const std::vector<OrbisAudio3dAttribute>& attributes,
                          void* pcm);
};

} // namespace Libraries::Audio3d
