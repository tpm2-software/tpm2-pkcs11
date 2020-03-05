#ifndef SRC_LIB_STORE_CONFIG_H_
#define SRC_LIB_STORE_CONFIG_H_

/*
 * Defines the per-store config data.
 *
 * Since db.h depdend on the parser.h, define these here
 * to avoid a cyclic depndency of placing them in
 * db.h
 */
typedef struct store_config store_config;
struct store_config {
    const char *tcti;
    const char *loglevel;
};

#endif /* SRC_LIB_STORE_CONFIG_H_ */
