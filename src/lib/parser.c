/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <yaml.h>

#include "parser.h"
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

typedef struct kvp kvp;
struct kvp {
    const char *key;
    const char *value;
    const char *tag; /* Optional type constraint, like YAML TAG like YAML_BOOL_TAG */
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
    __clear_ptr((void **)&(state->h[state->depth]));

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
    bool res = __builtin_mul_overflow(state->cnt, sizeof(CK_ULONG), &bytes);
    if (res) {
        LOGE("mul overflow");
        return false;
    }

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
        res = handle_attr_event(&event, a, &state);

        if(event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }

        if (!res) {
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

bool kvp_get_tag(const char *needle, kvp *k, size_t len, const char **tag) {
    assert(needle);
    assert(k);

    size_t i;
    for (i=0; i < len; i++) {
        kvp *x = &k[i];
        assert(x->key);
        if (!strcmp(needle, x->key)) {
            if (tag) {
                *tag = x->tag;
            }
            return true;
        }
    }
    return false;
}

bool kvp_get_value(const char *key, kvp *k, size_t len, const char **value) {
    assert(key);
    assert(k);

    size_t i;
    for (i=0; i < len; i++) {
        kvp *x = &k[i];
        assert(x->key);
        if (!strcmp(key, x->key)) {
            *value = x->value;
            return true;
        }
    }
    return false;
}

void kvp_free(kvp *kvp_list, size_t kvp_list_len) {
    assert(kvp_list);

    size_t i;
    for (i=0; i < kvp_list_len; i++) {
        kvp *x = &kvp_list[i];
        free((void *)x->value);
    }
}

bool kvp_set_key(const char *key, const char *value,
        kvp *kvp_list, size_t kvp_list_len) {
    assert(key);

    /* nothing to do */
    if (!value) {
        return true;
    }

    size_t i;
    for (i=0; i < kvp_list_len; i++) {
        kvp *x = &kvp_list[i];
        if (!strcmp(key, x->key)) {
            char *dup = strdup(value);
            if (!dup) {
                LOGE("oom");
                return false;
            }
            x->value = dup;
            return true;
        }
    }
    return false;
}

static bool handle_event(yaml_event_t *e,
        config_state *state, kvp *kvp_list, size_t kvp_len) {

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

            const char *tag = NULL;
            bool has_key = kvp_get_tag(state->key,
                    kvp_list, kvp_len, &tag);
            if (!has_key) {
                LOGE("Unknown key: \"%s\"", state->key);
                return false;
            }

            if (tag) {
                bool tag_match = !strcmp(tag, (const char *)e->data.scalar.tag);
                if (!tag_match) {
                    LOGE("Expected tag of \"%s\", got: \"%s\"",
                            tag, e->data.scalar.tag);
                    return false;
                }
            }

            bool set_ok = kvp_set_key(state->key, (const char *)e->data.scalar.value,
                    kvp_list, kvp_len);
            if (!set_ok) {
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

static bool generic_kvp_parse(const unsigned char *yaml, size_t size,
        kvp *kvp_list, size_t kvp_len) {

    bool rv = false;

    yaml_parser_t parser;

    int rc = yaml_parser_initialize(&parser);
    if(!rc) {
        return false;
    }

    yaml_parser_set_input_string(&parser, yaml, size);

    config_state state = { 0 };

    yaml_event_t event;
    yaml_event_type_t event_type = YAML_NO_EVENT;
    do {
        int rc = yaml_parser_parse(&parser, &event);
        if (!rc) {
            LOGE("Parser error %d", parser.error);
            goto error;
        }

        /* handle events */
        bool result = handle_event(&event, &state,
                kvp_list, kvp_len);
        event_type = event.type;
        yaml_event_delete(&event);
        if (!result) {
            LOGE("Parser error %d", parser.error);
            goto error;
        }
    } while(event_type != YAML_STREAM_END_EVENT);

    rv = true;

out:
    yaml_parser_delete(&parser);

    return rv;
error:
    kvp_free(kvp_list, kvp_len);
    goto out;
}

bool parse_token_config_from_string_v2(const unsigned char *yaml, size_t size, token_config_v2 *config) {

    bool rc = false;

    kvp kvp_list[] = {
        { .key = "token-init", .value = NULL, .tag = YAML_BOOL_TAG },
        { .key = "tcti",       .value = NULL, .tag = YAML_STR_TAG }, /* ignored */
        { .key = "log-level",  .value = NULL, .tag = YAML_INT_TAG }  /* ignored */
    };

    bool result = generic_kvp_parse(yaml, size, kvp_list, ARRAY_LEN(kvp_list));
    if (!result) {
        return false;
    }

    const char *value = NULL;
    result = kvp_get_value("token-init", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"token-init\"");
        goto out;
    }

    if (!value) {
        LOGE("Expected token config key \"token-init\"");
        goto out;
    }

    config->is_initialized = !strcmp(value, "true")
                            ? true : false;

    /* all is well */
    rc = true;

out:
    kvp_free(kvp_list, ARRAY_LEN(kvp_list));
    return rc;
}

bool parse_token_config_from_string_v1(const unsigned char *yaml, size_t size, token_config_v1 *config) {

    bool rc = false;

    kvp kvp_list[] = {
        { .key = "token-init", .value = NULL, .tag = YAML_BOOL_TAG },
        { .key = "tcti",       .value = NULL, .tag = YAML_STR_TAG },
        { .key = "log-level",  .value = NULL, .tag = YAML_INT_TAG }
    };

    bool result = generic_kvp_parse(yaml, size, kvp_list, ARRAY_LEN(kvp_list));
    if (!result) {
        return false;
    }

    const char *value = NULL;
    result = kvp_get_value("token-init", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"token-init\"");
        goto out;
    }

    if (!value) {
        LOGE("Expected token config key \"token-init\"");
        goto out;
    }

    config->is_initialized = !strcmp(value, "true")
                            ? true : false;

    value = NULL;
    result = kvp_get_value("tcti", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"tcti\"");
        goto out;
    }

    if (value) {
        config->tcti = strdup(value);
        if (!config->tcti) {
            LOGE("oom");
            goto out;
        }
    }

    result = kvp_get_value("log-level", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"log-level\"");
        goto out;
    }

    if (value) {
        config->loglevel = strdup(value);
        if (!config->loglevel) {
            free((void *)config->tcti);
            LOGE("oom");
            goto out;
        }
    }

    /* all is well */
    rc = true;

out:
    kvp_free(kvp_list, ARRAY_LEN(kvp_list));
    return rc;
}

bool parse_store_config_from_string(const unsigned char *yaml, size_t size, store_config *config) {

    bool rc = false;

    kvp kvp_list[] = {
        { .key = "tcti",      .value = NULL, .tag = YAML_STR_TAG },
        { .key = "log-level", .value = NULL, .tag = YAML_INT_TAG }
    };

    bool result = generic_kvp_parse(yaml, size, kvp_list, ARRAY_LEN(kvp_list));
    if (!result) {
        return false;
    }

    const char *value = NULL;
    result = kvp_get_value("tcti", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"tcti\"");
        goto out;
    }

    if (value) {
        config->tcti = strdup(value);
        if (!config->tcti) {
            LOGE("oom");
            goto out;
        }
    }

    result = kvp_get_value("log-level", kvp_list, ARRAY_LEN(kvp_list), &value);
    if (!result) {
        LOGE("Could not retrieve value for key \"log-level\"");
        goto out;
    }

    if (value) {
        config->loglevel = strdup(value);
        if (!config->loglevel) {
            free((void *)config->tcti);
            LOGE("oom");
            goto out;
        }
    }

    /* all is well */
    rc = true;

out:
    kvp_free(kvp_list, ARRAY_LEN(kvp_list));
    return rc;
}
