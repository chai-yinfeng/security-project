#include <stdio.h>
#include "license_api.h"

static int protected_main(void) {
    puts("protected path entered");
    return 0;
}

int main(void) {
    if (license_check() != LICENSE_ALLOW) {
        fputs("license denied\n", stderr);
        return 1;
    }

    return protected_main();
}