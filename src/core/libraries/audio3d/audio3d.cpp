// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/logging/log.h"
#include "core/libraries/audio/audioout.h"
#include "core/libraries/audio3d/audio3d.h"
#include "core/libraries/audio3d/audio3d_context.h"
#include "core/libraries/audio3d/audio3d_error.h"
#include "core/libraries/error_codes.h"
#include "core/libraries/libs.h"

namespace Libraries::Audio3d {

static std::unique_ptr<Audio3dContext> context;

int PS4_SYSV_ABI sceAudio3dAudioOutClose() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dAudioOutOpen(OrbisAudio3dPortId port_id, OrbisUserServiceUserId user_id,
                                        AudioOut::OrbisAudioOutPort type, s32 index, u32 len,
                                        u32 freq,
                                        AudioOut::OrbisAudioOutParamExtendedInformation param) {
    return context->AudioOutOpen(port_id, user_id, type, index, len, freq, param);
}

int PS4_SYSV_ABI sceAudio3dAudioOutOutput(s32 handle, void* ptr) {
    return context->AudioOutOutput(handle, ptr);
}

int PS4_SYSV_ABI sceAudio3dAudioOutOutputs(AudioOut::OrbisAudioOutOutputParam* param,
                                           uint32_t num) {
    return AudioOut::sceAudioOutOutputs(param, num);
}

int PS4_SYSV_ABI sceAudio3dBedWrite(OrbisAudio3dPortId port_id, u32 num_channels,
                                    OrbisAudio3dFormat format, const uintptr_t buffer,
                                    u32 num_samples) {
    return sceAudio3dBedWrite2(port_id, num_channels, format, buffer, num_samples,
                               ORBIS_AUDIO3D_OUTPUT_BOTH, false);
}

int PS4_SYSV_ABI sceAudio3dBedWrite2(OrbisAudio3dPortId port_id, u32 num_channels,
                                     OrbisAudio3dFormat format, const uintptr_t buffer,
                                     u32 num_samples, OrbisAudio3dOutputRoute output_route,
                                     bool restricted) {
    return context->BedWrite2(port_id, num_channels, format, buffer, num_samples, output_route,
                              restricted);
}

int PS4_SYSV_ABI sceAudio3dCreateSpeakerArray() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dDeleteSpeakerArray() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dGetDefaultOpenParameters() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dGetSpeakerArrayMemorySize() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dGetSpeakerArrayMixCoefficients() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dGetSpeakerArrayMixCoefficients2() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dInitialize(const s64 reserved) {
    if (reserved != 0) {
        return ORBIS_AUDIO3D_ERROR_INVALID_PARAMETER;
    }

    if (context) {
        return ORBIS_AUDIO3D_ERROR_NOT_READY;
    }

    context = std::make_unique<Audio3dContext>();
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dObjectReserve(const OrbisAudio3dPortId port_id,
                                         OrbisAudio3dObjectId* id) {
    return context->ObjectReserve(port_id, id);
}

int PS4_SYSV_ABI sceAudio3dObjectSetAttributes(OrbisAudio3dPortId port_id,
                                               OrbisAudio3dObjectId object_id,
                                               size_t num_attributes,
                                               const OrbisAudio3dAttribute* attribute_array) {
    return context->ObjectSetAttributes(port_id, object_id, num_attributes, attribute_array);
}

int PS4_SYSV_ABI sceAudio3dObjectUnreserve() {
    LOG_DEBUG(Lib_Audio3d, "(DUMMY) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortAdvance(OrbisAudio3dPortId port_id) {
    return context->PortAdvance(port_id);
}

int PS4_SYSV_ABI sceAudio3dPortClose(OrbisAudio3dPortId port_id) {
    return context->PortClose(port_id);
}

int PS4_SYSV_ABI sceAudio3dPortCreate() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortDestroy() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortFlush() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortFreeState() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortGetAttributesSupported() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortGetList() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortGetParameters() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortGetQueueLevel(OrbisAudio3dPortId port_id, u32* queue_level,
                                             u32* queue_available) {
    return context->PortGetQueueLevel(port_id, queue_level, queue_available);
}

int PS4_SYSV_ABI sceAudio3dPortGetState() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortGetStatus() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortOpen(OrbisUserServiceUserId user_id,
                                    const OrbisAudio3dOpenParameters* parameters,
                                    OrbisAudio3dPortId* id) {
    return context->PortOpen(user_id, parameters, id);
}

int PS4_SYSV_ABI sceAudio3dPortPush(OrbisAudio3dPortId port_id, OrbisAudio3dBlocking blocking) {
    return context->PortPush(port_id, blocking);
}

int PS4_SYSV_ABI sceAudio3dPortQueryDebug() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dPortSetAttribute() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dReportRegisterHandler() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dReportUnregisterHandler() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dSetGpuRenderer() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dStrError() {
    LOG_ERROR(Lib_Audio3d, "(STUBBED) called");
    return ORBIS_OK;
}

int PS4_SYSV_ABI sceAudio3dTerminate() {
    if (!context) {
        return ORBIS_AUDIO3D_ERROR_NOT_READY;
    }

    LOG_DEBUG(Lib_Audio3d, "(DUMMY) called");
    return ORBIS_OK;
}

void RegisterlibSceAudio3d(Core::Loader::SymbolsResolver* sym) {
    LIB_FUNCTION("pZlOm1aF3aA", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dAudioOutClose);
    LIB_FUNCTION("ucEsi62soTo", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dAudioOutOpen);
    LIB_FUNCTION("7NYEzJ9SJbM", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dAudioOutOutput);
    LIB_FUNCTION("HbxYY27lK6E", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dAudioOutOutputs);
    LIB_FUNCTION("9tEwE0GV0qo", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dBedWrite);
    LIB_FUNCTION("xH4Q9UILL3o", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dBedWrite2);
    LIB_FUNCTION("lvWMW6vEqFU", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dCreateSpeakerArray);
    LIB_FUNCTION("8hm6YdoQgwg", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dDeleteSpeakerArray);
    LIB_FUNCTION("Im+jOoa5WAI", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dGetDefaultOpenParameters);
    LIB_FUNCTION("kEqqyDkmgdI", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dGetSpeakerArrayMemorySize);
    LIB_FUNCTION("-R1DukFq7Dk", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dGetSpeakerArrayMixCoefficients);
    LIB_FUNCTION("-Re+pCWvwjQ", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dGetSpeakerArrayMixCoefficients2);
    LIB_FUNCTION("UmCvjSmuZIw", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dInitialize);
    LIB_FUNCTION("jO2tec4dJ2M", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dObjectReserve);
    LIB_FUNCTION("4uyHN9q4ZeU", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dObjectSetAttributes);
    LIB_FUNCTION("1HXxo-+1qCw", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dObjectUnreserve);
    LIB_FUNCTION("lw0qrdSjZt8", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortAdvance);
    LIB_FUNCTION("OyVqOeVNtSk", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortClose);
    LIB_FUNCTION("UHFOgVNz0kk", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortCreate);
    LIB_FUNCTION("Mw9mRQtWepY", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortDestroy);
    LIB_FUNCTION("ZOGrxWLgQzE", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortFlush);
    LIB_FUNCTION("uJ0VhGcxCTQ", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortFreeState);
    LIB_FUNCTION("9ZA23Ia46Po", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dPortGetAttributesSupported);
    LIB_FUNCTION("SEggctIeTcI", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortGetList);
    LIB_FUNCTION("flPcUaXVXcw", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dPortGetParameters);
    LIB_FUNCTION("YaaDbDwKpFM", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dPortGetQueueLevel);
    LIB_FUNCTION("CKHlRW2E9dA", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortGetState);
    LIB_FUNCTION("iRX6GJs9tvE", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortGetStatus);
    LIB_FUNCTION("XeDDK0xJWQA", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortOpen);
    LIB_FUNCTION("VEVhZ9qd4ZY", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dPortPush);
    LIB_FUNCTION("-pzYDZozm+M", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dPortQueryDebug);
    LIB_FUNCTION("Yq9bfUQ0uJg", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dPortSetAttribute);
    LIB_FUNCTION("QfNXBrKZeI0", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dReportRegisterHandler);
    LIB_FUNCTION("psv2gbihC1A", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dReportUnregisterHandler);
    LIB_FUNCTION("yEYXcbAGK14", "libSceAudio3d", 1, "libSceAudio3d", 1, 1,
                 sceAudio3dSetGpuRenderer);
    LIB_FUNCTION("Aacl5qkRU6U", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dStrError);
    LIB_FUNCTION("WW1TS2iz5yc", "libSceAudio3d", 1, "libSceAudio3d", 1, 1, sceAudio3dTerminate);
};

} // namespace Libraries::Audio3d