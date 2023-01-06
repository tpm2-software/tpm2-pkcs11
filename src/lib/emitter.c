/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include <yaml.h>

#include "attrs.h"
#include "emitter.h"
#include "log.h"
#include "pkcs11.h"
#include "twist.h"
#include "token.h"
#include "typed_memory.h"

typedef struct yaml_emitter_state yaml_emitter_state;
struct yaml_emitter_state {
    char *buf;
    size_t size;
};

static int output_handler(void *data, unsigned char *buffer, size_t size) {

    yaml_emitter_state *s = (yaml_emitter_state *)data;

    size_t newsize = 0;
    safe_add(newsize, s->size, size);

    size_t newsize_1 = 0;
    safe_add(newsize_1, newsize, 1);

    void *ptr = realloc(s->buf, newsize_1);
    if (!ptr) {
        free(s->buf);
        return 0;
    }
    s->buf = ptr;

    size_t size_1 = 0;
    safe_add(size_1, size, 1);

    memset(&s->buf[s->size], 0, size_1);
    memcpy(&s->buf[s->size], buffer, size);

    s->size = newsize;

    return 1;
}

WEAK char *emit_attributes_to_string(attr_list *attrs) {

    yaml_document_t doc = { 0 };

    char *yaml_return = NULL;

    int rc = yaml_document_initialize(&doc,
            NULL, /* version directive */
            NULL, /* directive start */
            NULL, /* directive end */
            0, /* start implicit */
            0); /* end implicit */
    if (!rc) {
        LOGE("doc init failed");
        return NULL;
    }

    int root = yaml_document_add_mapping(&doc, NULL,
            YAML_ANY_MAPPING_STYLE);
    if (!root) {
        LOGE("root add failed");
        goto doc_delete;
    }

    CK_ULONG count = attr_list_get_count(attrs);
    const CK_ATTRIBUTE_PTR _attrs = attr_list_get_ptr(attrs);

    CK_ULONG i;
    for (i=0; i < count; i++) {

        /* handle the key */
        const CK_ATTRIBUTE_PTR a = &_attrs[i];

        char strkey[64] = { 0 };
        CK_ATTRIBUTE_TYPE k = a->type;
        snprintf(strkey, sizeof(strkey), "%"PRIu64"", k);

        int key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_INT_TAG,
             (yaml_char_t *)strkey, -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        /* what type of value is it */
        CK_BYTE type = type_from_ptr(a->pValue, a->ulValueLen);
        assert(type);

        yaml_char_t *yamltag = NULL;
        switch(type) {
            case TYPE_BYTE_INT:
                yamltag = (yaml_char_t *)YAML_INT_TAG;
                break;
            case TYPE_BYTE_BOOL:
                yamltag = (yaml_char_t *)YAML_BOOL_TAG;
                break;
            case TYPE_BYTE_INT_SEQ:
                yamltag = (yaml_char_t *)YAML_SEQ_TAG;
                break;
            case TYPE_BYTE_HEX_STR:
                yamltag = (yaml_char_t *)YAML_STR_TAG;
                break;
            default:
                LOGE("unknown type, perhaps memory corruption issue?");
                goto doc_delete;
        }

        int node;

        /*
         * handle the value
         */
        if (type != TYPE_BYTE_INT_SEQ) {

            char keyvaluebuf[64] = { 0 };
            const char *keyvalue = NULL;
            if (type == TYPE_BYTE_INT) {
                CK_ULONG_PTR v = (CK_ULONG_PTR)a->pValue;
                snprintf(keyvaluebuf, sizeof(keyvaluebuf), "%"PRIu64"", *v);
                keyvalue = keyvaluebuf;
            } else if (type == TYPE_BYTE_BOOL) {
                CK_BBOOL *v = (CK_BBOOL *)a->pValue;
                snprintf(keyvaluebuf, sizeof(keyvaluebuf), "%s", *v == CK_TRUE ? "true" : "false");
                keyvalue = keyvaluebuf;
            } else if (type == TYPE_BYTE_HEX_STR) {
                /* string*/
                keyvalue = a->pValue ?
                        twist_hex_new(a->pValue, a->ulValueLen) : "";
                if (!keyvalue) {
                   LOGE("oom");
                   goto doc_delete;
                }
            } else {
                /* impossible */
                LOGE("barn fire");
                assert(0);
                goto doc_delete;
            }

            node = yaml_document_add_scalar(&doc, yamltag,
                 (yaml_char_t *)keyvalue, -1, YAML_ANY_SCALAR_STYLE);
            if (type == TYPE_BYTE_HEX_STR && strcmp(keyvalue, "")) {
                twist_free(keyvalue);
            }
            if (!node) {
                LOGE("yaml_document_add_scalar for value failed");
                goto doc_delete;
            }

        } else {
            /* start a sequence */
            node = yaml_document_add_sequence(&doc,
                    yamltag, YAML_ANY_SEQUENCE_STYLE);
            if (!node) {
                LOGE("yaml_document_add_sequence for value failed");
                goto doc_delete;
            }

            /* add scalar int's to sequence */
            CK_ULONG len = a->ulValueLen/sizeof(CK_ULONG);
            CK_ULONG j;
            for (j=0; j < len; j++) {

                CK_ULONG v = ((CK_ULONG_PTR)a->pValue)[j];

                char keyvalue[64] = { 0 };
                snprintf(keyvalue, sizeof(keyvalue), "%"PRIu64"", v);

                /* create a scalar */
                int seqscalar = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_INT_TAG,
                     (yaml_char_t *)keyvalue, -1, YAML_ANY_SCALAR_STYLE);
                if (!seqscalar) {
                    LOGE("yaml_document_add_scalar for value failed");
                    goto doc_delete;
                }

                /* add scalar to sequence */
                rc = yaml_document_append_sequence_item(&doc,
                        node, seqscalar);
                if (!rc) {
                    LOGE("yaml_document_append_sequence_item for value failed");
                    goto doc_delete;
                }
            }
        }

        /* add either scalar value or sequence of values */
        rc = yaml_document_append_mapping_pair(&doc,
                root, key, node);
        if (!rc) {
            LOGE("yaml_document_append_mapping_pair failed");
            goto doc_delete;
        }
    }

    yaml_emitter_t emitter = { 0 };

    /* dummy dump the yaml to get size */
    if (!yaml_emitter_initialize(&emitter)) {
        LOGE("Could not inialize the emitter object");
        goto doc_delete;
    }

    yaml_emitter_state state = { 0 };

    yaml_emitter_set_output(&emitter, output_handler, &state);

    yaml_emitter_set_canonical(&emitter, 1);

    if (!yaml_emitter_dump(&emitter, &doc)) {
        free(state.buf);
        LOGE("dump failed");
        goto emitter_delete;
    }

    if (!yaml_emitter_close(&emitter)) {
        free(state.buf);
        LOGE("close failed");
        goto emitter_delete;
    }

    yaml_return =  state.buf;

emitter_delete:
    yaml_emitter_delete(&emitter);

doc_delete:
    yaml_document_delete(&doc);

    return yaml_return;

}

WEAK char *emit_config_to_string(token *t) {

    yaml_document_t doc = { 0 };

    char *yaml_return = NULL;

    int rc = yaml_document_initialize(&doc,
            NULL, /* version directive */
            NULL, /* directive start */
            NULL, /* directive end */
            0, /* start implicit */
            0); /* end implicit */
    if (!rc) {
        LOGE("doc init failed");
        return NULL;
    }

    int root = yaml_document_add_mapping(&doc, NULL,
            YAML_ANY_MAPPING_STYLE);
    if (!root) {
        LOGE("root add failed");
        goto doc_delete;
    }

    /* add config value is initialized */
    int key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
         (yaml_char_t *)"token-init", -1, YAML_ANY_SCALAR_STYLE);
    if (!key) {
        LOGE("yaml_document_add_scalar for key failed");
        goto doc_delete;
    }

    const char *value = t->config.is_initialized ? "true" : "false";

    int node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_BOOL_TAG,
         (yaml_char_t *)value, -1, YAML_ANY_SCALAR_STYLE);

    rc = yaml_document_append_mapping_pair(&doc,
            root, key, node);
    if (!rc) {
        LOGE("yaml_document_append_mapping_pair failed");
        goto doc_delete;
    }

    /* add the tcti config value */
    if (t->config.tcti) {
        key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)"tcti", -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)t->config.tcti, -1, YAML_ANY_SCALAR_STYLE);

        rc = yaml_document_append_mapping_pair(&doc,
                root, key, node);
        if (!rc) {
            LOGE("yaml_document_append_mapping_pair failed");
            goto doc_delete;
        }
    }

    /* add the pss signature state if known */
    if (t->config.pss_sigs_good != pss_config_state_unk) {

        key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)"pss-sigs-good", -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        value = (t->config.pss_sigs_good == pss_config_state_good)
                ? "true" : "false";

        node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_BOOL_TAG,
             (yaml_char_t *)value, -1, YAML_ANY_SCALAR_STYLE);

        rc = yaml_document_append_mapping_pair(&doc,
                root, key, node);
        if (!rc) {
            LOGE("yaml_document_append_mapping_pair failed");
            goto doc_delete;
        }
    }

    /* add config value empty user PIN, if set */
    if (t->config.empty_user_pin) {
        key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)"empty-user-pin", -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        int node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_BOOL_TAG,
             (yaml_char_t *)"true", -1, YAML_ANY_SCALAR_STYLE);

        rc = yaml_document_append_mapping_pair(&doc,
                root, key, node);
        if (!rc) {
            LOGE("yaml_document_append_mapping_pair failed");
            goto doc_delete;
        }
    }

    yaml_emitter_t emitter = { 0 };

    /* dummy dump the yaml to get size */
    if (!yaml_emitter_initialize(&emitter)) {
        LOGE("Could not inialize the emitter object");
        goto doc_delete;
    }

    yaml_emitter_state state = { 0 };

    yaml_emitter_set_output(&emitter, output_handler, &state);

    yaml_emitter_set_canonical(&emitter, 1);

    if (!yaml_emitter_dump(&emitter, &doc)) {
        free(state.buf);
        LOGE("dump failed");
        goto emitter_delete;
    }

    if (!yaml_emitter_close(&emitter)) {
        free(state.buf);
        LOGE("close failed");
        goto emitter_delete;
    }

    yaml_return =  state.buf;

emitter_delete:
    yaml_emitter_delete(&emitter);

doc_delete:
    yaml_document_delete(&doc);

    return yaml_return;

}

WEAK char *emit_pobject_to_conf_string(pobject_config *config) {

    yaml_document_t doc = { 0 };

    char *yaml_return = NULL;

    int rc = yaml_document_initialize(&doc,
            NULL, /* version directive */
            NULL, /* directive start */
            NULL, /* directive end */
            0, /* start implicit */
            0); /* end implicit */
    if (!rc) {
        LOGE("doc init failed");
        return NULL;
    }

    int root = yaml_document_add_mapping(&doc, NULL,
            YAML_ANY_MAPPING_STYLE);
    if (!root) {
        LOGE("root add failed");
        goto doc_delete;
    }

    /* add config value is transient */
    int key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
         (yaml_char_t *)"transient", -1, YAML_ANY_SCALAR_STYLE);
    if (!key) {
        LOGE("yaml_document_add_scalar for key failed");
        goto doc_delete;
    }

    const char *value = config->is_transient ? "true" : "false";

    int node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_BOOL_TAG,
         (yaml_char_t *)value, -1, YAML_ANY_SCALAR_STYLE);

    rc = yaml_document_append_mapping_pair(&doc,
            root, key, node);
    if (!rc) {
        LOGE("yaml_document_append_mapping_pair failed");
        goto doc_delete;
    }

    /* add the template-name config value  if is transient */
    if (config->is_transient) {
        assert(config->template_name);
        key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)"template-name", -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)config->template_name, -1, YAML_ANY_SCALAR_STYLE);
    } else {
        /* it is persistent add the esys tr */
        assert(config->blob);
        key = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)"esys-tr", -1, YAML_ANY_SCALAR_STYLE);
        if (!key) {
            LOGE("yaml_document_add_scalar for key failed");
            goto doc_delete;
        }

        twist hexblob = twist_hexlify(config->blob);
        if (!hexblob) {
            goto doc_delete;
        }

        node = yaml_document_add_scalar(&doc, (yaml_char_t *)YAML_STR_TAG,
             (yaml_char_t *)hexblob, -1, YAML_ANY_SCALAR_STYLE);
        twist_free(hexblob);
    }

    /* add either template-name or esys-tr */
    rc = yaml_document_append_mapping_pair(&doc,
            root, key, node);
    if (!rc) {
        LOGE("yaml_document_append_mapping_pair failed");
        goto doc_delete;
    }

    yaml_emitter_t emitter = { 0 };

    /* dummy dump the yaml to get size */
    if (!yaml_emitter_initialize(&emitter)) {
        LOGE("Could not inialize the emitter object");
        goto doc_delete;
    }

    yaml_emitter_state state = { 0 };

    yaml_emitter_set_output(&emitter, output_handler, &state);

    yaml_emitter_set_canonical(&emitter, 1);

    if (!yaml_emitter_dump(&emitter, &doc)) {
        free(state.buf);
        LOGE("dump failed");
        goto emitter_delete;
    }

    if (!yaml_emitter_close(&emitter)) {
        free(state.buf);
        LOGE("close failed");
        goto emitter_delete;
    }

    yaml_return =  state.buf;

emitter_delete:
    yaml_emitter_delete(&emitter);

doc_delete:
    yaml_document_delete(&doc);

    return yaml_return;
}
