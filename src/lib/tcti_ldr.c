/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include <tss2/tss2_sys.h>

#include "log.h"
#include "tcti_ldr.h"
#include "utils.h"

#define TPM2_PKCS11_TCTI "TPM2_PKCS11_TCTI"

typedef struct tcti_conf tcti_conf;
struct tcti_conf {
    const char *name;
    const char *opts;
};

static void *handle;
static const TSS2_TCTI_INFO *info;

bool tpm2_tcti_ldr_is_tcti_present(const char *name) {

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "libtss2-tcti-%s.so", name);

    void *handle = dlopen (path, RTLD_LAZY);
    if (handle) {
        dlclose(handle);
    }

    return handle != NULL;
}

TSS2_TCTI_CONTEXT *tpm2_tcti_ldr_load(const char *path, const char *opts) {

    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    if (!handle) {
        /*
         * Try what they gave us, if it doesn't load up, try
         * libtss2-tcti-xxx.so replacing xxx with what they gave us.
         */
        handle = dlopen (path, RTLD_LAZY);
        if (!handle) {

            char buf[PATH_MAX];
            size_t size = snprintf(buf, sizeof(buf), "libtss2-tcti-%s.so", path);
            if (size >= sizeof(buf)) {
                LOGE("Truncated friendly name conversion, got: \"%s\", made: \"%s\"",
                        path, buf);
                return NULL;
            }

            handle = dlopen (buf, RTLD_LAZY);
            if (!handle) {
                LOGE("Could not dlopen library: \"%s\"", buf);
                return NULL;
            }
        }

    }

    TSS2_TCTI_INFO_FUNC infofn = (TSS2_TCTI_INFO_FUNC)dlsym(handle, TSS2_TCTI_INFO_SYMBOL);
    if (!infofn) {
        LOGE("Symbol \"%s\"not found in library: \"%s\"",
                TSS2_TCTI_INFO_SYMBOL, path);
        goto err;
    }

    info = infofn();

    TSS2_TCTI_INIT_FUNC init = info->init;

    size_t size;
    TSS2_RC rc = init(NULL, &size, opts);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("tcti init setup routine failed for library: \"%s\""
                " options: \"%s\"", path, opts);
        goto err;
    }

    tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOGE("oom");
        goto err;
    }

    rc = init(tcti_ctx, &size, opts);
    if (rc != TPM2_RC_SUCCESS) {
        LOGE("tcti init allocation routine failed for library: \"%s\""
                " options: \"%s\"", path, opts);
        goto err;
    }

    return tcti_ctx;

err:
    free(tcti_ctx);
    dlclose(handle);
    return NULL;
}

static inline const char *fixup_name(const char *name) {

    return !strcmp(name, "abrmd") ? "tabrmd" : name;
}

const char *find_default_tcti(void) {

    const char *defaults[] = {
        "tabrmd",
        "device",
        "mssim"
    };

    size_t i;
    for(i=0; i < ARRAY_LEN(defaults); i++) {
        const char *name = defaults[i];
        bool is_present = tpm2_tcti_ldr_is_tcti_present(name);
        if (is_present) {
            return name;
        }
    }

    return NULL;
}

tcti_conf tcti_get_config(void) {

    /* set up the default configuration */
    tcti_conf conf = {
        .name = find_default_tcti()
    };

    /* no tcti config supplied, get it from env */
    char *optstr = getenv (TPM2_PKCS11_TCTI);
    if (!optstr) {
        /* nothing user supplied, use default */
        return conf;
    }

    char *split = strchr(optstr, ':');
    if (!split) {
        /* --tcti=device */
        conf.name = fixup_name(optstr);
        return conf;
    }

    /*
     * If it has a ":", it could be either one of the following:
     * case A: --tcti=:               --> default name and default (null) config
     * case B: --tcti=:/dev/foo       --> default name, custom config
     * case C: --tcti=device:         --> custom name, default (null) config
     * case D: --tcti=device:/dev/foo --> custom name, custom config
     */

    split[0] = '\0';

    /* Case A */
    if (!optstr[0] && !split[1]) {
        return conf;
    }

    /* Case B */
    if (!optstr[0]) {
        conf.opts = &split[1];
        return conf;
    }

    /* Case C */
    if (!split[1]) {
        conf.name = fixup_name(optstr);
        return conf;
    }

    /* Case D */
    conf.name = fixup_name(optstr);
    conf.opts = &split[1];
    return conf;
}

TSS2_TCTI_CONTEXT *tcti_ldr_load(void) {

    tcti_conf conf = tcti_get_config();
    return tpm2_tcti_ldr_load(conf.name, conf.opts);
}

void tcti_ldr_unload(void) {
    if (handle) {
#ifndef DISABLE_DLCLOSE
        dlclose(handle);
#endif
        handle = NULL;
        info = NULL;
    }
}
