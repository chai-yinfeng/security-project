#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>

static const char *SE_KEY_TAG = "coms6424.license-demo.device-binding";

static SecKeyRef find_existing_key(void) {
    CFDataRef tag = CFDataCreate(
        kCFAllocatorDefault,
        (const UInt8 *)SE_KEY_TAG,
        strlen(SE_KEY_TAG)
    );

    const void *keys[] = {
        kSecClass, kSecAttrKeyClass, kSecAttrKeyType,
        kSecAttrApplicationTag, kSecReturnRef, kSecMatchLimit,
        kSecAttrTokenID
    };
    const void *values[] = {
        kSecClassKey, kSecAttrKeyClassPrivate, kSecAttrKeyTypeECSECPrimeRandom,
        tag, kCFBooleanTrue, kSecMatchLimitOne,
        kSecAttrTokenIDSecureEnclave
    };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 7,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);

    CFRelease(query);
    CFRelease(tag);

    if (status == errSecSuccess) return key;
    if (status != errSecItemNotFound) {
        fprintf(stderr, "se_keygen: SecItemCopyMatching status=%d\n", (int)status);
    }
    return NULL;
}

static SecKeyRef create_se_key(void) {
    CFDataRef tag = CFDataCreate(
        kCFAllocatorDefault,
        (const UInt8 *)SE_KEY_TAG,
        strlen(SE_KEY_TAG)
    );

    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        NULL
    );
    if (!access) {
        fprintf(stderr, "se_keygen: SecAccessControlCreateWithFlags failed\n");
        CFRelease(tag);
        return NULL;
    }

    CFMutableDictionaryRef priv_attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(priv_attrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(priv_attrs, kSecAttrApplicationTag, tag);
    CFDictionarySetValue(priv_attrs, kSecAttrAccessControl, access);

    int bits = 256;
    CFNumberRef key_size = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, key_size);
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, priv_attrs);

    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(params, &error);

    CFRelease(params);
    CFRelease(priv_attrs);
    CFRelease(access);
    CFRelease(key_size);
    CFRelease(tag);

    if (!key && error) {
        CFStringRef desc = CFErrorCopyDescription(error);
        char buf[512];
        CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
        fprintf(stderr, "se_keygen: %s\n", buf);
        CFRelease(desc);
        CFRelease(error);
    }

    return key;
}

static int export_public_key_hex(SecKeyRef private_key) {
    SecKeyRef public_key = SecKeyCopyPublicKey(private_key);
    if (!public_key) {
        fprintf(stderr, "se_keygen: SecKeyCopyPublicKey failed\n");
        return 1;
    }

    CFErrorRef error = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(public_key, &error);
    CFRelease(public_key);

    if (!data) {
        fprintf(stderr, "se_keygen: SecKeyCopyExternalRepresentation failed\n");
        if (error) CFRelease(error);
        return 1;
    }

    const UInt8 *bytes = CFDataGetBytePtr(data);
    CFIndex len = CFDataGetLength(data);

    for (CFIndex i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");

    CFRelease(data);
    return 0;
}

int main(void) {
    SecKeyRef key = find_existing_key();
    if (!key) {
        key = create_se_key();
        if (!key) {
            fprintf(stderr, "se_keygen: failed to create or find SE key\n");
            return 1;
        }
    }

    int result = export_public_key_hex(key);
    CFRelease(key);
    return result;
}
