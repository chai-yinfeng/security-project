#ifndef PACKAGE_CORE_H
#define PACKAGE_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LICENSE_DENY = 0,
    LICENSE_ALLOW = 1
} license_decision_t;

/*
 * Production runtime entry point for the self-checking executable.
 * The implementation is expected to inspect the current executable image,
 * read the embedded signed policy/blob, query the live runtime environment,
 * and return ALLOW or DENY.
 */
license_decision_t license_check_embedded_policy(void);

#ifdef __cplusplus
}
#endif

#endif
