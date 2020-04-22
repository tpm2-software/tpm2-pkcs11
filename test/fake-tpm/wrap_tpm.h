/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TEST_WRAP_TPM_H_
#define TEST_WRAP_TPM_H_
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include <openssl/rand.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include "utils.h"

TSS2_RC __wrap_Esys_Create(
        ESYS_CONTEXT *esysContext,
        ESYS_TR parentHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_PUBLIC *inPublic,
        const TPM2B_DATA *outsideInfo,
        const TPML_PCR_SELECTION *creationPCR,
        TPM2B_PRIVATE **outPrivate,
        TPM2B_PUBLIC **outPublic,
        TPM2B_CREATION_DATA **creationData,
        TPM2B_DIGEST **creationHash,
        TPMT_TK_CREATION **creationTicket) {

    UNUSED(esysContext);
    UNUSED(parentHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inSensitive);
    UNUSED(inPublic);
    UNUSED(outsideInfo);
    UNUSED(creationPCR);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PUBLIC *pub = NULL;
    TPM2B_PRIVATE *priv = NULL;
    TPM2B_CREATION_DATA *cdata = NULL;
    TPM2B_DIGEST *chash = NULL;
    TPMT_TK_CREATION *cticket = NULL;

    pub = calloc(1, sizeof(*pub));
    if (!pub) { goto oom; }
    *pub = *inPublic;

    priv = calloc(1, sizeof(*priv));
    if (!priv) { goto oom; }

    priv->size = 42;
    memset(priv->buffer, 0xFF, priv->size);

    cdata = calloc(1, sizeof(*cdata));
    if (!cdata) { goto oom; }

    chash = calloc(1, sizeof(*chash));
    if (!chash) { goto oom; }

    cticket = calloc(1, sizeof(*cticket));
    if (!cticket) { goto oom; }

    *outPrivate = priv;
    *outPublic = pub;
    *creationData = cdata;
    *creationHash = chash;
    *creationTicket = cticket;

    return rc;
oom:
    free(pub);
    free(priv);
    free(cdata);
    free(chash);
    free(cticket);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_CreateLoaded(
        ESYS_CONTEXT *esysContext,
        ESYS_TR parentHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_TEMPLATE *template,
        ESYS_TR *objectHandle,
        TPM2B_PRIVATE **outPrivate,
        TPM2B_PUBLIC **outPublic){

    UNUSED(esysContext);
    UNUSED(parentHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inSensitive);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PUBLIC *pub = NULL;
    TPM2B_PRIVATE *priv = NULL;

    pub = calloc(1, sizeof(*pub));
    if (!pub) { goto oom; }

    size_t offset = 0;
    TSS2_RC rv = Tss2_MU_TPMT_PUBLIC_Unmarshal(template->buffer, template->size, &offset,
            &pub->publicArea);
    if (rv != TSS2_RC_SUCCESS) {
        LOGE("Template unmarshal shouldn't fail, got: %lu", rv);
        free(pub);
        return rv;
    }

    priv = calloc(1, sizeof(*priv));
    if (!priv) { goto oom; }

    *outPrivate = priv;
    *outPublic = pub;
    *objectHandle = 42;

    return rc;
oom:
    free(pub);
    free(priv);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_CreatePrimary(
        ESYS_CONTEXT *esysContext,
        ESYS_TR primaryHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *inSensitive,
        const TPM2B_PUBLIC *inPublic,
        const TPM2B_DATA *outsideInfo,
        const TPML_PCR_SELECTION *creationPCR,
        ESYS_TR *objectHandle,
        TPM2B_PUBLIC **outPublic,
        TPM2B_CREATION_DATA **creationData,
        TPM2B_DIGEST **creationHash,
        TPMT_TK_CREATION **creationTicket){

    UNUSED(esysContext);
    UNUSED(primaryHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inSensitive);
    UNUSED(inPublic);
    UNUSED(outsideInfo);
    UNUSED(creationPCR);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PUBLIC *pub = NULL;
    TPM2B_CREATION_DATA *cdata = NULL;
    TPM2B_DIGEST *chash = NULL;
    TPMT_TK_CREATION *cticket = NULL;

    pub = calloc(1, sizeof(*pub));
    if (!pub) { goto oom; }
    *pub = *inPublic;

    cdata = calloc(1, sizeof(*cdata));
    if (!cdata) { goto oom; }

    chash = calloc(1, sizeof(*chash));
    if (!chash) { goto oom; }

    cticket = calloc(1, sizeof(*cticket));
    if (!cticket) { goto oom; }

    *outPublic = pub;
    *creationData = cdata;
    *creationHash = chash;
    *creationTicket = cticket;

    *objectHandle = 42;

    return rc;
oom:
    free(pub);
    free(cdata);
    free(chash);
    free(cticket);

    return TSS2_ESYS_RC_MEMORY;

}

TSS2_RC __wrap_Esys_EncryptDecrypt(
        ESYS_CONTEXT *esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPMI_YES_NO decrypt,
        TPMI_ALG_SYM_MODE mode,
        const TPM2B_IV *ivIn,
        const TPM2B_MAX_BUFFER *inData,
        TPM2B_MAX_BUFFER **outData,
        TPM2B_IV **ivOut) {

    UNUSED(esysContext);
    UNUSED(keyHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(decrypt);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_MAX_BUFFER *data_out = NULL;
    TPM2B_IV *iv_out = NULL;

    data_out = calloc(1, sizeof(*data_out));
    if (!data_out) { goto oom; }

    /* shuffle the data */
    data_out->size = inData->size;
    memcpy(data_out->buffer, inData->buffer, inData->size);

    iv_out = calloc(1, sizeof(*iv_out));
    if (!iv_out) { goto oom; }

    *outData = data_out;
    *ivOut = iv_out;

    return rc;
oom:
    free(data_out);
    free(iv_out);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_EncryptDecrypt2(
        ESYS_CONTEXT *esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_MAX_BUFFER *inData,
        TPMI_YES_NO decrypt,
        TPMI_ALG_SYM_MODE mode,
        const TPM2B_IV *ivIn,
        TPM2B_MAX_BUFFER **outData,
        TPM2B_IV **ivOut){

    UNUSED(esysContext);
    UNUSED(keyHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(decrypt);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_MAX_BUFFER *data_out = NULL;
    TPM2B_IV *iv_out = NULL;

    data_out = calloc(1, sizeof(*data_out));
    if (!data_out) { goto oom; }

    /* shuffle the data */
    data_out->size = inData->size;
    memcpy(data_out->buffer, inData->buffer, inData->size);

    iv_out = calloc(1, sizeof(*iv_out));
    if (!iv_out) { goto oom; }

    *outData = data_out;
    *ivOut = iv_out;

    return rc;
oom:
    free(data_out);
    free(iv_out);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_EvictControl(
        ESYS_CONTEXT *esysContext,
        ESYS_TR auth,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPMI_DH_PERSISTENT persistentHandle,
        ESYS_TR *newObjectHandle) {

    UNUSED(esysContext);
    UNUSED(auth);
    UNUSED(objectHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(persistentHandle);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *newObjectHandle = 69;

    return rc;
}

TSS2_RC __wrap_Esys_Finalize(ESYS_CONTEXT **context) {

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *context = NULL;
    return rc;
}

TSS2_RC __wrap_Esys_FlushContext(
        ESYS_CONTEXT *esysContext,
        ESYS_TR flushHandle) {

    UNUSED(esysContext);
    UNUSED(flushHandle);

    return mock();
}

TSS2_RC __wrap_Esys_Free(void *__ptr) {

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    free(__ptr);
    return rc;
}

static inline TSS2_RC get_commands(UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        const TPMS_CAPABILITY_DATA **capabilityData) {

    if (property != TPM2_CC_FIRST) {
        return TPM2_RC_P | TPM2_RC_2 | TPM2_RC_VALUE;
    }

    if (propertyCount != TPM2_MAX_CAP_CC) {
        return TPM2_RC_P | TPM2_RC_3 | TPM2_RC_VALUE;
    }

    *moreData = TPM2_NO;

    static const TPMS_CAPABILITY_DATA _data = {
        .capability = TPM2_CAP_COMMANDS,
        .data = {
            .command = {
                /* tpm2_getcap commands | grep value: | sort | cut -d: -f 2-2 | sed s/' '// | wc -l */
                .count = 113,
                /* for v in `tpm2_getcap commands | grep value: | sort | cut -d: -f 2-2 | sed s/' '//`; do echo $v,; done; */
                .commandAttributes = {
                        0x10000161,
                        0x10000167,
                        0x10000186,
                        0x12000131,
                        0x12000157,
                        0x1200015B,
                        0x12000191,
                        0x14000176,
                        0x165,
                        0x178,
                        0x17A,
                        0x17B,
                        0x17C,
                        0x17D,
                        0x17E,
                        0x181,
                        0x18A,
                        0x18E,
                        0x20000000,
                        0x2000130,
                        0x2000153,
                        0x2000154,
                        0x2000155,
                        0x2000156,
                        0x2000158,
                        0x2000159,
                        0x200015C,
                        0x200015D,
                        0x200015E,
                        0x2000162,
                        0x2000163,
                        0x2000164,
                        0x2000168,
                        0x2000169,
                        0x200016A,
                        0x200016B,
                        0x200016C,
                        0x200016D,
                        0x200016E,
                        0x200016F,
                        0x2000170,
                        0x2000171,
                        0x2000172,
                        0x2000173,
                        0x2000174,
                        0x2000177,
                        0x200017F,
                        0x2000180,
                        0x2000183,
                        0x2000187,
                        0x2000188,
                        0x2000189,
                        0x200018B,
                        0x200018C,
                        0x200018D,
                        0x200018F,
                        0x2000190,
                        0x2000193,
                        0x20400211,
                        0x20400212,
                        0x20400213,
                        0x2400127,
                        0x2400128,
                        0x2400129,
                        0x240012A,
                        0x240012B,
                        0x240012C,
                        0x240012D,
                        0x240012E,
                        0x2400132,
                        0x2400139,
                        0x240013A,
                        0x240013B,
                        0x240013C,
                        0x240013D,
                        0x240013F,
                        0x2400140,
                        0x2400182,
                        0x2C00121,
                        0x2C00124,
                        0x2C00125,
                        0x2C00126,
                        0x300013E,
                        0x4000147,
                        0x4000148,
                        0x400014A,
                        0x400014B,
                        0x400014C,
                        0x400014E,
                        0x4000150,
                        0x4000151,
                        0x4000152,
                        0x4000160,
                        0x400142,
                        0x400143,
                        0x400144,
                        0x400145,
                        0x400146,
                        0x440011F,
                        0x4400120,
                        0x4400122,
                        0x4400133,
                        0x4400134,
                        0x4400135,
                        0x4400136,
                        0x4400137,
                        0x4400138,
                        0x440014F,
                        0x5400185,
                        0x6000149,
                        0x600014D,
                        0x6000184,
                        0x6000192,
                },
            },
        },
    };

    *capabilityData = &_data;

    return TSS2_RC_SUCCESS;
}

static inline TSS2_RC get_algs(UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        const TPMS_CAPABILITY_DATA **capabilityData) {

    if (property != TPM2_ALG_FIRST) {
        return TPM2_RC_P | TPM2_RC_2 | TPM2_RC_VALUE;
    }

    if (propertyCount != TPM2_MAX_CAP_ALGS) {
        return TPM2_RC_P | TPM2_RC_3 | TPM2_RC_VALUE;
    }

    *moreData = TPM2_NO;

    static const TPMS_CAPABILITY_DATA _data = {
        .capability = TPM2_CAP_ALGS,
        .data = {
            .algorithms = {
                /* tpm2_getcap algorithms | grep value: | sort | wc -l */
                .count = 26,
                /* alg, properties */
                /* for v in `tpm2_getcap algorithms | grep value: | cut -d: -f 2-2 | sed s/' '//`; do echo "{$v,},"; done; */
                /* hand jammed the rest, notice no sort, need order to be same to match alg with property */
                .algProperties = {
                    {0x1, 0x9},
                    {0x4, 0x4},
                    {0x5, 0x104},
                    {0x6, 0x2},
                    {0x7, 0x404},
                    {0x8, 0x30C},
                    {0xA, 0x6},
                    {0xB, 0x4},
                    {0xC, 0x4},
                    {0x14, 0x101},
                    {0x15, 0x201},
                    {0x16, 0x101},
                    {0x17, 0x201},
                    {0x18, 0x501},
                    {0x19, 0x401},
                    {0x1A, 0x101},
                    {0x1C, 0x101},
                    {0x20, 0x404},
                    {0x22, 0x404},
                    {0x23, 0x9},
                    {0x25, 0x8},
                    {0x40, 0x202},
                    {0x41, 0x202},
                    {0x42, 0x202},
                    {0x43, 0x202},
                    {0x44, 0x202},
                },
            },
        },
    };

    *capabilityData = &_data;

    return TSS2_RC_SUCCESS;
}

static inline TSS2_RC get_properties(UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        const TPMS_CAPABILITY_DATA **capabilityData) {

    if (property != TPM2_PT_FIXED) {
        return TPM2_RC_P | TPM2_RC_2 | TPM2_RC_VALUE;
    }

    if (propertyCount != TPM2_MAX_TPM_PROPERTIES) {
        return TPM2_RC_P | TPM2_RC_3 | TPM2_RC_VALUE;
    }

    *moreData = TPM2_NO;

    static const TPMS_CAPABILITY_DATA _data = {
        .capability = TPM2_CAP_TPM_PROPERTIES,
        .data = {
            .tpmProperties = {
                /* tpm2_getcap properties-fixed | grep raw | wc -l */
                .count = 44,
                /* python script
                 *   - https://gist.github.com/williamcroberts/15c3b7721a74cf5e0f1e9c733a88e511
                 * with this patch applied to tpm2-tools:
                 *   - https://github.com/tpm2-software/tpm2-tools/pull/1986
                 */
                .tpmProperty = {
                    {.property=TPM2_PT_FIRMWARE_VERSION_2, .value=0x162800},
                    {.property=TPM2_PT_FIRMWARE_VERSION_1, .value=0x20160511},
                    {.property=TPM2_PT_NV_COUNTERS_MAX, .value=0x0},
                    {.property=TPM2_PT_PCR_COUNT, .value=0x18},
                    {.property=TPM2_PT_PS_REVISION, .value=0x92},
                    {.property=TPM2_PT_CLOCK_UPDATE, .value=0x1000},
                    {.property=TPM2_PT_MEMORY, .value=0x6},
                    {.property=TPM2_PT_INPUT_BUFFER, .value=0x400},
                    {.property=TPM2_PT_SPLIT_MAX, .value=0x80},
                    {.property=TPM2_PT_DAY_OF_YEAR, .value=0xA7},
                    {.property=TPM2_PT_YEAR, .value=0x7E1},
                    {.property=TPM2_PT_HR_LOADED_MIN, .value=0x3},
                    {.property=TPM2_PT_PS_YEAR, .value=0x7E1},
                    {.property=TPM2_PT_LIBRARY_COMMANDS, .value=0x6D},
                    {.property=TPM2_PT_REVISION, .value=0x92},
                    {.property=TPM2_PT_VENDOR_COMMANDS, .value=0x4},
                    {.property=TPM2_PT_MODES, .value=0x0},
                    {.property=TPM2_PT_MAX_SESSION_CONTEXT, .value=0x144},
                    {.property=TPM2_PT_HR_TRANSIENT_MIN, .value=0x3},
                    {.property=TPM2_PT_TOTAL_COMMANDS, .value=0x71},
                    {.property=TPM2_PT_FAMILY_INDICATOR, .value=0x322E3000},
                    {.property=TPM2_PT_PS_FAMILY_INDICATOR, .value=0x322E3000},
                    {.property=TPM2_PT_ORDERLY_COUNT, .value=0xFF},
                    {.property=TPM2_PT_MAX_DIGEST, .value=0x30},
                    {.property=TPM2_PT_NV_BUFFER_MAX, .value=0x400},
                    {.property=TPM2_PT_MAX_COMMAND_SIZE, .value=0x1000},
                    {.property=TPM2_PT_VENDOR_STRING_1, .value=0x53572020},
                    {.property=TPM2_PT_VENDOR_STRING_3, .value=0x0},
                    {.property=TPM2_PT_VENDOR_STRING_2, .value=0x2054504D},
                    {.property=TPM2_PT_CONTEXT_SYM_SIZE, .value=0x100},
                    {.property=TPM2_PT_VENDOR_STRING_4, .value=0x0},
                    {.property=TPM2_PT_CONTEXT_GAP_MAX, .value=0xFFFFFFFF},
                    {.property=TPM2_PT_CONTEXT_HASH, .value=0xC},
                    {.property=TPM2_PT_MANUFACTURER, .value=0x49424D20},
                    {.property=TPM2_PT_CONTEXT_SYM, .value=0x6},
                    {.property=TPM2_PT_MAX_RESPONSE_SIZE, .value=0x1000},
                    {.property=TPM2_PT_NV_INDEX_MAX, .value=0x800},
                    {.property=TPM2_PT_LEVEL, .value=0x0},
                    {.property=TPM2_PT_PS_LEVEL, .value=0x0},
                    {.property=TPM2_PT_HR_PERSISTENT_MIN, .value=0x2},
                    {.property=TPM2_PT_PCR_SELECT_MIN, .value=0x3},
                    {.property=TPM2_PT_PS_DAY_OF_YEAR, .value=0xA7},
                    {.property=TPM2_PT_ACTIVE_SESSIONS_MAX, .value=0x40},
                    {.property=TPM2_PT_MAX_OBJECT_CONTEXT, .value=0x764},
                    {.property=TPM2_PT_VENDOR_TPM_TYPE, .value=0x1},
                },
            },
        },
    };

    *capabilityData = &_data;

    return TSS2_RC_SUCCESS;
}


/* TODO THIS ONE IS HARD PROBABLY CAPTURE ACTUAL DUMPS AND MEMCPY HERE */
TSS2_RC __wrap_Esys_GetCapability(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2_CAP capability,
        UINT32 property,
        UINT32 propertyCount,
        TPMI_YES_NO *moreData,
        TPMS_CAPABILITY_DATA **capabilityData) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    const TPMS_CAPABILITY_DATA *tmp = NULL;

    TSS2_RC rc = TSS2_RC_SUCCESS;

    switch (capability) {
    case TPM2_CAP_COMMANDS:
        rc = get_commands(property, propertyCount, moreData, &tmp);
        break;
    case TPM2_CAP_ALGS:
        rc = get_algs(property, propertyCount, moreData, &tmp);
        break;
    case TPM2_CAP_TPM_PROPERTIES:
        rc = get_properties(property, propertyCount, moreData, &tmp);
        break;
    default:
        return TPM2_RC_S | TPM2_RC_1 | TPM2_RC_HANDLE;
    }

    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* allocate a new place to store the data to */
    TPMS_CAPABILITY_DATA *data = calloc(1, sizeof(*data));
    if (!data) {
        return TSS2_ESYS_RC_MEMORY;
    }

    /* copy the static tpm data to it */
    *data = *tmp;

    /* return good pointer to user */
    *capabilityData = data;

    return rc;
}

TSS2_RC __wrap_Esys_GetRandom(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        UINT16 bytesRequested,
        TPM2B_DIGEST **randomBytes) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_DIGEST *rdata = calloc(1, sizeof(*rdata));
    if (!rdata) {
        return TSS2_ESYS_RC_MEMORY;
    }

    rdata->size = bytesRequested;
    memset(rdata->buffer, 0xAA, sizeof(rdata->buffer));

    *randomBytes = rdata;

    return rc;
}

TSS2_RC __wrap_Esys_Initialize(
        ESYS_CONTEXT **esys_context,
        TSS2_TCTI_CONTEXT *tcti,
        TSS2_ABI_VERSION *abiVersion) {

    UNUSED(tcti);
    UNUSED(abiVersion);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    /* We should never be looking at this in the app anyways */
    *esys_context = (void *)0xDEADBEEF;

    return rc;
}

TSS2_RC __wrap_Esys_Load(
        ESYS_CONTEXT *esysContext,
        ESYS_TR parentHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_PRIVATE *inPrivate,
        const TPM2B_PUBLIC *inPublic,
        ESYS_TR *objectHandle) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inPrivate);
    UNUSED(inPublic);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *objectHandle = 81;

    return rc;
}

TSS2_RC __wrap_Esys_LoadExternal(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE *inPrivate,
        const TPM2B_PUBLIC *inPublic,
        ESYS_TR hierarchy,
        ESYS_TR *objectHandle) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inPrivate);
    UNUSED(inPublic);
    UNUSED(hierarchy);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *objectHandle = 101;
    return rc;
}

TSS2_RC __wrap_Esys_ObjectChangeAuth(
        ESYS_CONTEXT *esysContext,
        ESYS_TR objectHandle,
        ESYS_TR parentHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_AUTH *newAuth,
        TPM2B_PRIVATE **outPrivate) {

    UNUSED(esysContext);
    UNUSED(parentHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(newAuth);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PRIVATE *priv = NULL;

    priv = calloc(1, sizeof(*priv));
    if (!priv) { goto oom; }

    priv->size = 42;
    memset(priv->buffer, 0xFF, priv->size);

    *outPrivate = priv;

    return rc;
oom:
    free(priv);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_ReadPublic(
        ESYS_CONTEXT *esysContext,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_PUBLIC **outPublic,
        TPM2B_NAME **name,
        TPM2B_NAME **qualifiedName) {

    UNUSED(esysContext);
    UNUSED(objectHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PUBLIC *pub = NULL;

    pub = calloc(1, sizeof(*pub));
    if (!pub) { goto oom; }

    /*
     * This will be super brittle, the only use for this at the moment is to
     * get the namealg...
     *
     */
    pub->publicArea.nameAlg = TPM2_ALG_SHA256;

    *outPublic = pub;

    return rc;
oom:
    free(pub);

    return TSS2_ESYS_RC_MEMORY;
}

TSS2_RC __wrap_Esys_RSA_Decrypt(
        ESYS_CONTEXT *esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_PUBLIC_KEY_RSA *cipherText,
        const TPMT_RSA_DECRYPT *inScheme,
        const TPM2B_DATA *label,
        TPM2B_PUBLIC_KEY_RSA **message) {

    UNUSED(esysContext);
    UNUSED(keyHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inScheme);
    UNUSED(label);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_PUBLIC_KEY_RSA *msg = calloc(1, sizeof(*msg));
    if (!msg) {
        return TSS2_ESYS_RC_MEMORY;
    }

    /* hmmm, might have to keep track of keysizes? */
    msg->size = 256;
    memset(msg->buffer, 'R', msg->size);

    return rc;
}

TSS2_RC __wrap_Esys_Sign(
        ESYS_CONTEXT *esysContext,
        ESYS_TR keyHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_DIGEST *digest,
        const TPMT_SIG_SCHEME *inScheme,
        const TPMT_TK_HASHCHECK *validation,
        TPMT_SIGNATURE **signature) {

    UNUSED(esysContext);
    UNUSED(keyHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(digest);
    UNUSED(inScheme);
    UNUSED(validation);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPMT_SIGNATURE *sig = calloc(1, sizeof(*sig));
    if (!sig) {
        return TSS2_ESYS_RC_MEMORY;
    }

    sig->sigAlg = TPM2_ALG_RSAPSS;
    sig->signature.rsapss.hash = TPM2_ALG_SHA256;

    /* hmm keysizes again */
    sig->signature.rsapss.sig.size = 256;
    memset(sig->signature.rsapss.sig.buffer, 'S', 256);

    *signature = sig;

    return rc;
}

TSS2_RC __wrap_Esys_StartAuthSession(
        ESYS_CONTEXT *esysContext,
        ESYS_TR tpmKey,
        ESYS_TR bind,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_NONCE *nonceCaller,
        TPM2_SE sessionType,
        const TPMT_SYM_DEF *symmetric,
        TPMI_ALG_HASH authHash,
        ESYS_TR *sessionHandle) {

    UNUSED(esysContext);
    UNUSED(tpmKey);
    UNUSED(bind);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(nonceCaller);
    UNUSED(sessionType);
    UNUSED(symmetric);
    UNUSED(authHash);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *sessionHandle = 0xBADCC0DE;

    return rc;
}

TSS2_RC __wrap_Esys_StirRandom(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPM2B_SENSITIVE_DATA *inData) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(inData);

    return mock();
}

static inline TSS2_RC test_rsa_params(TPMI_RSA_KEY_BITS bits) {

    if (bits == 1024 || bits == 2048) {
        return TSS2_RC_SUCCESS;
    }

    return TPM2_RC_P | TPM2_RC_1 | TPM2_RC_KEY_SIZE;
}

static inline TSS2_RC test_ecc_params(TPMI_ECC_CURVE curve) {

    if (curve == TPM2_ECC_NIST_P256 ||
            curve == TPM2_ECC_NIST_P384) {
        return TSS2_RC_SUCCESS;
    }

    return TPM2_RC_P | TPM2_RC_1 | TPM2_RC_CURVE;
}

TSS2_RC __wrap_Esys_TestParms(
        ESYS_CONTEXT *esysContext,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        const TPMT_PUBLIC_PARMS *parameters) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    /*
     * we intentionally don't mock this interface
     * as certain error codes are needed, so we just wire
     * this up to look like the simulator
     */
    switch(parameters->type) {
    case TPM2_ALG_RSA:
        return test_rsa_params(parameters->parameters.rsaDetail.keyBits);
    case TPM2_ALG_ECC:
        return test_ecc_params(parameters->parameters.eccDetail.curveID);
    default:
        return TPM2_RC_S | TPM2_RC_1 | TPM2_RC_HANDLE;
    }
}

TSS2_RC __wrap_Esys_TR_Deserialize(
        ESYS_CONTEXT *esys_context,
        uint8_t const *buffer,
        size_t buffer_size,
        ESYS_TR *esys_handle) {

    UNUSED(esys_context);
    UNUSED(buffer);
    UNUSED(buffer_size);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *esys_handle = 0xDE7EC7ED;

    return rc;
}

TSS2_RC __wrap_Esys_TR_FromTPMPublic(
        ESYS_CONTEXT *esysContext,
        TPM2_HANDLE tpm_handle,
        ESYS_TR optionalSession1,
        ESYS_TR optionalSession2,
        ESYS_TR optionalSession3,
        ESYS_TR *object) {

    UNUSED(esysContext);
    UNUSED(tpm_handle);
    UNUSED(optionalSession1);
    UNUSED(optionalSession2);
    UNUSED(optionalSession3);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *object = 0xBADCAFE;

    return rc;
}

TSS2_RC __wrap_Esys_TR_Serialize(
        ESYS_CONTEXT *esys_context,
        ESYS_TR object,
        uint8_t **buffer,
        size_t *buffer_size) {

    UNUSED(esys_context);
    UNUSED(object);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    uint8_t *b = calloc(1, 32);
    if (!b) {
        return TSS2_ESYS_RC_MEMORY;
    }

    memset(b, 'Q', 32);

    *buffer = b;

    return rc;
}

TSS2_RC __wrap_Esys_TRSess_GetAttributes(
        ESYS_CONTEXT *esysContext,
        ESYS_TR session,
        TPMA_SESSION *flags) {

    UNUSED(esysContext);
    UNUSED(session);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    *flags = 0xDE;

    return rc;
}

TSS2_RC __wrap_Esys_TRSess_SetAttributes(
        ESYS_CONTEXT *esysContext,
        ESYS_TR session,
        TPMA_SESSION flags,
        TPMA_SESSION mask) {

    UNUSED(esysContext);
    UNUSED(session);

    /* I think we can just bitbucket all this */
    UNUSED(flags);
    UNUSED(mask);

    return mock();
}

TSS2_RC __wrap_Esys_TR_SetAuth(
        ESYS_CONTEXT *esysContext,
        ESYS_TR handle,
        TPM2B_AUTH const *authValue) {

    UNUSED(esysContext);
    UNUSED(handle);
    UNUSED(authValue);

    return mock();
}

TSS2_RC __wrap_Esys_Unseal(
        ESYS_CONTEXT *esysContext,
        ESYS_TR itemHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_SENSITIVE_DATA **outData) {


    UNUSED(esysContext);
    UNUSED(itemHandle);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);

    TSS2_RC rc = mock();
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }

    TPM2B_SENSITIVE_DATA *data = calloc(1, sizeof(*data));
    if (!data) {
        return TSS2_ESYS_RC_MEMORY;
    }

    /* callers of this expect a 32 byte AES256 key */
    data->size = 32;
    memset(data->buffer, 'K', data->size);

    return rc;
}

CK_RV __wrap_backend_fapi_init(void) {
    return mock();
}

TSS2_RC __wrap_Tss2_TctiLdr_Initialize(
        const char *nameConf,
         TSS2_TCTI_CONTEXT **context) {
    UNUSED(nameConf);

    *context = (TSS2_TCTI_CONTEXT *)0xDEFACED;

    return mock();
}

TSS2_RC __wrap_Tss2_TctiLdr_Finalize(
         TSS2_TCTI_CONTEXT **context) {

    *context = NULL;

    return mock();
}

#endif /* TEST_WRAP_TPM_H_ */

