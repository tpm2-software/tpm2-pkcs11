/* SPDX-License-Identifier: BSD-2-Clause */
#include "config.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

#include "pkcs11.h"
#include "token.h"
#include "twist.h"
#include "typed_memory.h"
#include "utils.h"

#define MAX_DEPTH 2

typedef struct handler_state handler_state;
struct handler_state {
    bool is_value;
    size_t cnt;
    CK_ATTRIBUTE_TYPE key;
    size_t seqbytes;
    void *seqbuf;
};

typedef bool (*handler)(yaml_event_t *e, handler_state *state, attr_list *l);

typedef struct handler_stack handler_stack;
struct handler_stack {
    handler h[MAX_DEPTH];
    handler cur;
    size_t depth;

    handler_state state[MAX_DEPTH];
    handler_state *s;
};

bool push_handler(handler_stack *state, handler h) {

    if (state->depth >= MAX_DEPTH) {
        return false;
    }

    state->cur = h;
    state->h[state->depth] = h;
    state->s = &state->state[state->depth];
    state->depth++;

    return true;
}

#ifdef __clang_analyzer__
static inline void analyzer_free(void *p ) {
    assert(0);
    free(p);
}
#else
#define analyzer_free(x) UNUSED(x)
#endif

bool pop_handler(handler_stack *state) {

    if (state->depth == 0) {
        return false;
    }

    state->depth--;
    memset(&state->state[state->depth], 0, sizeof(state->state[state->depth]));
    /*
     * scan-build reports this as a leak of h, which is
     * invalid... you can't free fn pointers
     */
    analyzer_free(state->h[state->depth]);

    if (state->depth == 0) {
        state->cur = NULL;
        state->s = NULL;
        state->h[state->depth] = NULL;
    } else {
        state->cur = state->h[state->depth - 1];
        state->s = &state->state[state->depth - 1];
        state->cur = state->h[state->depth - 1];

        /*
         * state transitions only occur on sequences and thus the value portion
         * is complete
         */
        state->s->is_value = false;
    }

    return true;
}

static bool is_yaml_int(unsigned char *tag) {
    return !strcmp((const char *)tag, YAML_INT_TAG);
}

static bool is_yaml_bool(unsigned char *tag) {
    return !strcmp((const char *)tag, YAML_BOOL_TAG);
}

static bool is_yaml_str(unsigned char *tag) {
    return !strcmp((const char *)tag, YAML_STR_TAG);
}

typedef bool (*pfn_yaml_convert)(attr_list *l, CK_ATTRIBUTE_TYPE type, const yaml_char_t *value);

static bool yaml_convert_ulong(attr_list *l, CK_ATTRIBUTE_TYPE type, const yaml_char_t *value) {

    size_t val;
    int rc = str_to_ul((const char *)value, &val);
    if (rc) {
        return false;
    }

    return attr_list_add_int(l, type, val);
}

static bool yaml_convert_bbool(attr_list *l, CK_ATTRIBUTE_TYPE type, const yaml_char_t *value) {


    CK_BBOOL val = !strcmp((const char *)value, "true") ? CK_TRUE : CK_FALSE;

    return attr_list_add_bool(l, type, val);
}

static bool yaml_convert_hex_str(attr_list *l, CK_ATTRIBUTE_TYPE type, const yaml_char_t *value) {

    size_t len = 0;
    twist t = NULL;
    if (!value || strlen((const char *)value)) {
        t = twistbin_unhexlify((const char *)value);
        if (!t) {
            LOGE("Could not unhexlify, got: \"%s\"", value);
            return false;
        }
        len = twist_len(t);
    }

    bool r = attr_list_add_buf(l, type, (CK_BYTE_PTR)t, len);
    twist_free(t);
    return r;
}

bool on_map_scalar_event(yaml_event_t *e, handler_state *state, attr_list *l) {

    if (!e->data.scalar.tag) {
        LOGE("e->data.scalar.tag is NULL");
        return false;
    }

    if (!state->is_value) {
        if (!is_yaml_int(e->data.scalar.tag)) {
            LOGE("key should always be int, got: \"%s\"", e->data.scalar.tag);
            return false;
        }

        size_t val;
        int rc = str_to_ul((const char *)e->data.scalar.value, &val);
        if (rc) {
            return false;
        }

        state->key = val;

    } else  {

        pfn_yaml_convert pfn = NULL;

        if (is_yaml_int(e->data.scalar.tag)) {
            pfn = yaml_convert_ulong;
        } else if (is_yaml_bool(e->data.scalar.tag)) {
            pfn = yaml_convert_bbool;
        } else if (is_yaml_str(e->data.scalar.tag)) {
            pfn = yaml_convert_hex_str;
        } else {
            LOGE("unknown data type: %s", e->data.scalar.tag);
            return false;
        }

        bool res = pfn(l, state->key, e->data.scalar.value);
        if (!res) {
            return false;
        }
    }

    state->is_value = !state->is_value;

    return true;
}

bool on_seq_scalar_event(yaml_event_t *e, handler_state *state, attr_list *l) {
    UNUSED(l);

    if (!e->data.scalar.tag) {
        LOGE("Scalara tag is null");
        return false;
    }

    if (strcmp((const char *)e->data.scalar.tag, YAML_INT_TAG)) {
        LOGE("Attribute type key should always be int, got: \"%s\"",
                e->data.scalar.tag);
        return false;
    }

    state->cnt++;
    if (state->cnt == 0) {
        LOGE("add overflow");
        return false;
    }

    size_t bytes = 0;
    safe_mul(bytes, state->cnt, sizeof(CK_ULONG));

    void *tmp = realloc(state->seqbuf, bytes);
    if (!tmp) {
        LOGE("oom");
        return false;
    }

    state->seqbytes = bytes;

    CK_ULONG_PTR p = state->seqbuf = tmp;

    size_t val;
    int rc = str_to_ul((const char *)e->data.scalar.value, &val);
    if (rc) {
        return false;
    }

    p[state->cnt - 1] = val;

    return true;
}

bool handle_attr_event(yaml_event_t *event,
        attr_list *l, handler_stack *state) {

    bool res;

    switch(event->type) {
    case YAML_NO_EVENT:
    case YAML_STREAM_START_EVENT:
    case YAML_STREAM_END_EVENT:
    case YAML_DOCUMENT_START_EVENT:
    case YAML_DOCUMENT_END_EVENT:
        return true;
    case YAML_SEQUENCE_START_EVENT:
        return push_handler(state, on_seq_scalar_event);
    case YAML_SEQUENCE_END_EVENT:
        /* XXX we know that sequences never come first so the previous state (map) has the key */
        assert(state->s);
        res = attr_list_add_buf(l, state->state[0].key, state->s->seqbuf, state->s->seqbytes);
        free(state->s->seqbuf);
        state->s->seqbuf = NULL;
        if (!res) {
            LOGE("Cannot add seqence to attr list: 0x%lx", state->s->key);
            return res;
        }
        return pop_handler(state);
    case YAML_MAPPING_START_EVENT:
        return push_handler(state, on_map_scalar_event);
    case YAML_MAPPING_END_EVENT:
        return pop_handler(state);

    /* Data */
    case YAML_SCALAR_EVENT:

        if (!state->cur) {
            return false;
        }

        return state->cur(event, state->s, l);
    default:
        LOGE("Unhandled YAML event type: %u\n", event->type);
        return false;
    }

    return false;
}

#define ALLOC_SIZE 16

bool parse_attributes(yaml_parser_t *parser, attr_list **attrs) {

    bool res = false;

    attr_list *a = attr_list_new();
    if (!a) {
        LOGE("oom");
        return false;
    }

    yaml_event_t event;
    handler_stack state = { 0 };
    /* while events */
    do {

        int rc = yaml_parser_parse(parser, &event);
        if (!rc) {
            LOGE("Parser error %d\n", parser->error);
            goto error;
        }

        /* handle events */
        bool tmp_res = handle_attr_event(&event, a, &state);

        if(event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }

        if (!tmp_res) {
            goto error;
        }


    } while(event.type != YAML_STREAM_END_EVENT);

    *attrs = a;

    res = true;

error:

    /* make sure sequf is always freed */
    free(state.state[0].seqbuf);
    free(state.state[1].seqbuf);

    if (!res) {
        attr_list_free(a);
    }

    yaml_event_delete(&event);

    return res;
}

bool parse_attributes_from_string(const unsigned char *yaml, size_t size,
        attr_list **attrs) {

    yaml_parser_t parser;

    int rc = yaml_parser_initialize(&parser);
    if(!rc) {
        return false;
    }

    yaml_parser_set_input_string(&parser, yaml, size);

    bool ret = parse_attributes(&parser, attrs);
    yaml_parser_delete(&parser);
    return ret;
}

typedef struct config_state config_state;
struct config_state {
    bool map_start;
    char key[64];
};

bool handle_config_event(yaml_event_t *e,
        config_state *state, token_config *config) {

    switch(e->type) {
    case YAML_NO_EVENT:
    case YAML_STREAM_START_EVENT:
    case YAML_STREAM_END_EVENT:
    case YAML_DOCUMENT_START_EVENT:
    case YAML_DOCUMENT_END_EVENT:
        return true;
    case YAML_MAPPING_START_EVENT:
        if (state->map_start) {
            return false;
        }
        state->map_start = true;
        return true;
    case YAML_MAPPING_END_EVENT:
        if (!state->map_start) {
            return false;
        }
        state->map_start = false;
        return true;

    /* Data */
    case YAML_SCALAR_EVENT:
        if (!state->map_start) {
            return false;
        }

        /* key */
        if (!strlen(state->key)) {
            if (!is_yaml_str(e->data.scalar.tag)) {
                LOGE("Cannot handle non-str config keys, got: \"%s\"\n",
                        e->data.scalar.value);
                return false;
            }

            if (e->data.scalar.length > sizeof(state->key) - 1) {
                LOGE("Key is too big for storage class, got key \"%s\","
                        " expected less than %zu", e->data.scalar.value,
                        sizeof(state->key) - 1);
                return false;
            }

            snprintf(state->key, sizeof(state->key), "%s",
                    e->data.scalar.value);
        } else {

            if (!strcmp(state->key, "tcti")) {
                config->tcti = strdup((const char *)e->data.scalar.value);
                if (!config->tcti) {
                    LOGE("oom");
                    return false;
                }
            } else if(!strcmp(state->key, "token-init")) {
                config->is_initialized = !strcmp((const char *)e->data.scalar.value, "true")
                        ? true : false;
            } else if(!strcmp(state->key, "pss-sigs-good")) {
                config->pss_sigs_good = !strcmp((const char *)e->data.scalar.value, "true")
                        ? pss_config_state_good : pss_config_state_bad;
            } else {
                LOGE("Unknown key, got: \"%s\"\n",
                        state->key);
                return false;
            }

            state->key[0] = '\0';
        }
        return true;
    default:
        LOGE("Unhandled YAML event type: %u\n", e->type);
    }

    return false;
}

bool parse_token_config_from_string(const unsigned char *yaml, size_t size, token_config *config) {

    yaml_parser_t parser;

    int rc = yaml_parser_initialize(&parser);
    if(!rc) {
        return false;
    }

    yaml_parser_set_input_string(&parser, yaml, size);

    config_state state = { 0 };

    yaml_event_t event;
    do {
        int rc = yaml_parser_parse(&parser, &event);
        if (!rc) {
            LOGE("Parser error %d", parser.error);
            return false;
        }

        /* handle events */
        rc = handle_config_event(&event, &state, config);
        if (!rc) {
            LOGE("Parser error %d", parser.error);
            return false;
        }

        if(event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }

    } while(event.type != YAML_STREAM_END_EVENT);

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);

    return true;
}
