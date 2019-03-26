/* SPDX-License-Identifier: BSD-2 */
/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 */
#ifndef SRC_PKCS11_LOG_H_
#define SRC_PKCS11_LOG_H_

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#if defined (__GNUC__)
#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#else
#define COMPILER_ATTR(...)
#endif

typedef enum log_level log_level;
enum log_level {
    log_level_error,
    log_level_warn,
    log_level_verbose,
    log_level_unknown,
};
static const char *log_strings[] = {
    "ERROR",
    "WARNING",
    "INFO",
    "UNKNOWN",
};

#define LOGV(fmt, ...) _log(log_level_verbose, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) _log(log_level_warn, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) _log(log_level_error, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

static inline void _log(log_level level, const char *file, unsigned lineno,
        const char *fmt,...) {

    log_level current_log_level = log_level_error;
    const char *env_level = getenv("TPM2_PKCS11_LOG_LEVEL");
    if (env_level) {
        char *endptr;
        errno = 0;
        unsigned long value = strtoul(env_level, &endptr, 0);
        if (errno || *endptr != '\0') {
            fprintf(stderr, "Could not change log level, got: \"%s\"\n", env_level);
            return;
        }

        /*
         * Use a switch to check value, as enum may be signed or
         * unsigned and when unsigned checking less than can cause
         * the compiler to complain.
         */
        switch(value) {
            case log_level_error:
            case log_level_warn:
            case log_level_verbose:
                current_log_level = value;
                break;
            default:
                fprintf(stderr, "Could not change log level, got: \"%s\"\n", env_level);
                return;
        }
    }

    /* Skip printing messages outside of the log level */
    if (level > current_log_level) {
        return;
    }

    va_list argptr;
    va_start(argptr, fmt);

    /* Verbose output prints file and line on error */
    if (current_log_level >= log_level_verbose) {
        fprintf(stderr, "%s on line: \"%u\" in file: \"%s\": ",
                log_strings[level], lineno, file);
    }
    else {
        fprintf(stderr, "%s: ", log_strings[level]);
    }

    /* Print the user supplied message */
    vfprintf(stderr, fmt, argptr);

    /* always add a new line so the user doesn't have to */
    fprintf(stderr, "\n");

    va_end(argptr);
}

#endif /* SRC_PKCS11_LOG_H_ */
