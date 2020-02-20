/* SPDX-License-Identifier: BSD-2-Clause */

#include "config.h"
#include "backend.h"
#include "backend_esysdb.h"

/* This file includes the logic for selecting, aggregating and
 * distributing calls to different backends.
 * For now this will only be the esysdb backend that uses tss2-esys
 * and sqlite3 for operations.
 * In the future, logic will be added to also inlcude the tss2-fapi
 * library for storage and TPM interaction.
 */

CK_RV backend_init(void) {
    return backend_esysdb_init();
}

CK_RV backend_destroy(void) {
    return backend_esysdb_destroy();
}

/** Create a new token
 *
 * Create a new sealed object and store it in the data store.
 *
 * @param[in,out] t The token information on input and generated token
 *                  on output.
 * @param[in] hexwrappingkey TODO
 * @param[in] newauth The authorization value for the security operator
 *                    of the newly created token.
 * @param[in] newsalthex TODO
 * @returns TODO
 */
CK_RV backend_create_token_seal(token *t, const twist hexwrappingkey,
                       const twist newauth, const twist newsalthex) {
    return backend_esysdb_create_token_seal(t, hexwrappingkey, newauth, newsalthex);
}

/** Retrieve the all tokens available.
 *
 * The returned list is a set of all stored tokens with all
 * objects inside the token structure.
 * @param[out] tok The list of tokens.
 * @param[out] len The number of entries in tok.
 * @returns TODO
 */
CK_RV backend_get_tokens(token **tok, size_t *len) {
    return backend_esysdb_get_tokens(tok, len);
}
