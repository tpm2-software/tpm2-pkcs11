/* SPDX-License-Identifier: BSD-2-Clause */

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

#define _LOGV(filename, lineno, fmt, ...) _log(log_level_verbose, filename, lineno, fmt, ##__VA_ARGS__)
#define _LOGW(filename, lineno, fmt, ...) _log(log_level_warn,    filename, lineno, fmt, ##__VA_ARGS__)
#define _LOGE(filename, lineno, fmt, ...) _log(log_level_error,   filename, lineno, fmt, ##__VA_ARGS__)

#define LOGV(fmt, ...) _LOGV(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) _LOGW(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) _LOGE(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

static log_level _g_current_log_level = log_level_error;

static inline void log_set_level(const char *level_str) {

    if (!level_str) {
        return;
    }

    char *endptr;
    errno = 0;
    unsigned long value = strtoul(level_str, &endptr, 0);
    if (errno || *endptr != '\0') {
        fprintf(stderr, "Could not change log level, got: \"%s\"\n", level_str);
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
            _g_current_log_level = value;
            break;
        default:
            fprintf(stderr, "Could not change log level, got: \"%s\"\n", level_str);
            return;
    }
}

static inline void _log(log_level level, const char *file, unsigned lineno,
        const char *fmt,...) {

    /* override config with env var if set */
    log_set_level(getenv("TPM2_PKCS11_LOG_LEVEL"));


    /* Skip printing messages outside of the log level */
    if (level > _g_current_log_level) {
        return;
    }

    va_list argptr;
    va_start(argptr, fmt);

    /* Verbose output prints file and line on error */
    if (_g_current_log_level >= log_level_verbose) {
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
