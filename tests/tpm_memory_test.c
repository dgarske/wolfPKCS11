/* tpm_memory_test.c - TPM memory consumption test
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "unit.h"
#pragma GCC diagnostic pop
#include "../tpm_memory_test_data.h"
#include <wolfpkcs11/internal.h>

#if !defined(WOLFPKCS11_NO_STORE) && !defined(NO_RSA)

/* DLL Location and slot */
#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif
#ifndef WOLFPKCS11_DLL_SLOT
    #define WOLFPKCS11_DLL_SLOT 1
#endif

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = WOLFPKCS11_DLL_SLOT;

static byte* userPin = (byte*)"wolfpkcs11-test";
static CK_ULONG userPinLen;
static byte* soPin = (byte*)"wolfpkcs11-so-test";
static CK_ULONG soPinLen;
static unsigned char tokenName[] = "wolfPKCS11 Test Token";
static const char* libName = WOLFPKCS11_DLL_FILENAME;

/* Object classes and key types */
static CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
static CK_KEY_TYPE rsaKeyType = CKK_RSA;
static CK_CERTIFICATE_TYPE x509CertType = CKC_X_509;
static CK_BBOOL ckTrue = CK_TRUE;


/* Array to store object handles for cleanup */
static CK_OBJECT_HANDLE createdObjects[20];
static int objectCount = 0;

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN((const char*)tokenName));

    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");

    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;

    ret = funcList->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session for PIN setup");

    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login SO");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(session, userPin, userPinLen);
        CHECK_CKR(ret, "Init PIN");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_Logout(session);
        CHECK_CKR(ret, "Logout SO");
    }

    if (ret == CKR_OK) {
        ret = funcList->C_CloseSession(session);
        CHECK_CKR(ret, "Close Session for PIN setup");
    }

    return ret;
}

static CK_RV pkcs11_init(const char* library, CK_SESSION_HANDLE* session)
{
    CK_RV ret = CKR_OK;
#ifndef HAVE_PKCS11_STATIC
    void* func;

    dlib = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        ret = -1;
    }

    if (ret == CKR_OK) {
        func = (void*)(CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
        if (func == NULL) {
            fprintf(stderr, "Failed to get function list function\n");
            ret = -1;
        }
    }

    if (ret == CKR_OK) {
        ret = ((CK_C_GetFunctionList)func)(&funcList);
        CHECK_CKR(ret, "Get Function List call");
    }

    if (ret != CKR_OK && dlib != NULL)
        dlclose(dlib);

#else
    ret = C_GetFunctionList(&funcList);
    (void)library;
#endif

    if (ret == CKR_OK) {
        ret = funcList->C_Initialize(NULL);
        CHECK_CKR(ret, "Initialize");
    }

    if (ret == CKR_OK) {
        CK_FLAGS sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

        ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
        CHECK_CKR(ret, "Open Session");

        if (ret == CKR_OK && userPinLen != 0) {
            ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
            /* If login fails, try to initialize token and set PIN */
            if (ret != CKR_OK) {
                printf("Initial login failed. Attempting to initialize token...\n");
                funcList->C_CloseSession(*session);

                /* Initialize token */
                ret = pkcs11_init_token();
                if (ret == CKR_OK) {
                    /* Set user PIN */
                    ret = pkcs11_set_user_pin();
                }

                if (ret == CKR_OK) {
                    /* Reopen session and login */
                    ret = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, session);
                    CHECK_CKR(ret, "Reopen Session");

                    if (ret == CKR_OK) {
                        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
                        CHECK_CKR(ret, "Login after token init");
                    }
                }
            } else {
                CHECK_CKR(ret, "Login");
            }
        }
    }

    return ret;
}

static void pkcs11_final(CK_SESSION_HANDLE session)
{
    if (userPinLen != 0)
        funcList->C_Logout(session);
    funcList->C_CloseSession(session);

    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    dlclose(dlib);
#endif
}

static void cleanup_objects(CK_SESSION_HANDLE session)
{
    int i;
    for (i = 0; i < objectCount; i++) {
        funcList->C_DestroyObject(session, createdObjects[i]);
    }
    objectCount = 0;
}

/* Macro to define RSA key attributes for a specific key number */
#define DEFINE_RSA_KEY_TEMPLATE(num) \
    static CK_ATTRIBUTE rsa_key_template_##num[] = { \
        { CKA_CLASS,             &privKeyClass,     sizeof(privKeyClass)           }, \
        { CKA_KEY_TYPE,          &rsaKeyType,       sizeof(rsaKeyType)             }, \
        { CKA_DECRYPT,           &ckTrue,           sizeof(ckTrue)                 }, \
        { CKA_SIGN,              &ckTrue,           sizeof(ckTrue)                 }, \
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)                 }, \
        { CKA_PRIVATE,           &ckTrue,           sizeof(ckTrue)                 }, \
        { CKA_MODULUS,           rsa_##num##_modulus,  sizeof(rsa_##num##_modulus)   }, \
        { CKA_PRIVATE_EXPONENT,  rsa_##num##_priv_exp, sizeof(rsa_##num##_priv_exp)  }, \
        { CKA_PRIME_1,           rsa_##num##_p,        sizeof(rsa_##num##_p)         }, \
        { CKA_PRIME_2,           rsa_##num##_q,        sizeof(rsa_##num##_q)         }, \
        { CKA_EXPONENT_1,        rsa_##num##_dP,       sizeof(rsa_##num##_dP)        }, \
        { CKA_EXPONENT_2,        rsa_##num##_dQ,       sizeof(rsa_##num##_dQ)        }, \
        { CKA_COEFFICIENT,       rsa_##num##_u,        sizeof(rsa_##num##_u)         }, \
        { CKA_PUBLIC_EXPONENT,   rsa_##num##_pub_exp,  sizeof(rsa_##num##_pub_exp)   }, \
    }

/* Macro to define certificate template for a specific certificate number */
#define DEFINE_CERT_TEMPLATE(num) \
    static CK_ATTRIBUTE cert_template_##num[] = { \
        { CKA_CLASS,             &certClass,        sizeof(certClass)              }, \
        { CKA_CERTIFICATE_TYPE,  &x509CertType,     sizeof(x509CertType)           }, \
        { CKA_TOKEN,             &ckTrue,           sizeof(ckTrue)                 }, \
        { CKA_VALUE,             cert_##num##_der,  sizeof(cert_##num##_der)       }, \
    }

/* Define all RSA key templates */
DEFINE_RSA_KEY_TEMPLATE(1);
DEFINE_RSA_KEY_TEMPLATE(2);
DEFINE_RSA_KEY_TEMPLATE(3);
DEFINE_RSA_KEY_TEMPLATE(4);
DEFINE_RSA_KEY_TEMPLATE(5);
DEFINE_RSA_KEY_TEMPLATE(6);
DEFINE_RSA_KEY_TEMPLATE(7);
DEFINE_RSA_KEY_TEMPLATE(8);
DEFINE_RSA_KEY_TEMPLATE(9);
DEFINE_RSA_KEY_TEMPLATE(10);

/* Define all certificate templates */
DEFINE_CERT_TEMPLATE(1);
DEFINE_CERT_TEMPLATE(2);
DEFINE_CERT_TEMPLATE(3);
DEFINE_CERT_TEMPLATE(4);
DEFINE_CERT_TEMPLATE(5);
DEFINE_CERT_TEMPLATE(6);
DEFINE_CERT_TEMPLATE(7);
DEFINE_CERT_TEMPLATE(8);
DEFINE_CERT_TEMPLATE(9);
DEFINE_CERT_TEMPLATE(10);

/* Structure to hold template information */
typedef struct {
    CK_ATTRIBUTE* template;
    CK_ULONG count;
    const char* name;
} TemplateInfo;

static CK_RV create_rsa_keys_and_certs(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj;
    int i;

    /* Array of RSA key templates */
    TemplateInfo rsaTemplates[] = {
        { rsa_key_template_1,  sizeof(rsa_key_template_1)/sizeof(CK_ATTRIBUTE),  "RSA Key 1"  },
        { rsa_key_template_2,  sizeof(rsa_key_template_2)/sizeof(CK_ATTRIBUTE),  "RSA Key 2"  },
        { rsa_key_template_3,  sizeof(rsa_key_template_3)/sizeof(CK_ATTRIBUTE),  "RSA Key 3"  },
        { rsa_key_template_4,  sizeof(rsa_key_template_4)/sizeof(CK_ATTRIBUTE),  "RSA Key 4"  },
        { rsa_key_template_5,  sizeof(rsa_key_template_5)/sizeof(CK_ATTRIBUTE),  "RSA Key 5"  },
        { rsa_key_template_6,  sizeof(rsa_key_template_6)/sizeof(CK_ATTRIBUTE),  "RSA Key 6"  },
        { rsa_key_template_7,  sizeof(rsa_key_template_7)/sizeof(CK_ATTRIBUTE),  "RSA Key 7"  },
        { rsa_key_template_8,  sizeof(rsa_key_template_8)/sizeof(CK_ATTRIBUTE),  "RSA Key 8"  },
        { rsa_key_template_9,  sizeof(rsa_key_template_9)/sizeof(CK_ATTRIBUTE),  "RSA Key 9"  },
        { rsa_key_template_10, sizeof(rsa_key_template_10)/sizeof(CK_ATTRIBUTE), "RSA Key 10" },
    };

    /* Array of certificate templates */
    TemplateInfo certTemplates[] = {
        { cert_template_1,  sizeof(cert_template_1)/sizeof(CK_ATTRIBUTE),  "Certificate 1"  },
        { cert_template_2,  sizeof(cert_template_2)/sizeof(CK_ATTRIBUTE),  "Certificate 2"  },
        { cert_template_3,  sizeof(cert_template_3)/sizeof(CK_ATTRIBUTE),  "Certificate 3"  },
        { cert_template_4,  sizeof(cert_template_4)/sizeof(CK_ATTRIBUTE),  "Certificate 4"  },
        { cert_template_5,  sizeof(cert_template_5)/sizeof(CK_ATTRIBUTE),  "Certificate 5"  },
        { cert_template_6,  sizeof(cert_template_6)/sizeof(CK_ATTRIBUTE),  "Certificate 6"  },
        { cert_template_7,  sizeof(cert_template_7)/sizeof(CK_ATTRIBUTE),  "Certificate 7"  },
        { cert_template_8,  sizeof(cert_template_8)/sizeof(CK_ATTRIBUTE),  "Certificate 8"  },
        { cert_template_9,  sizeof(cert_template_9)/sizeof(CK_ATTRIBUTE),  "Certificate 9"  },
        { cert_template_10, sizeof(cert_template_10)/sizeof(CK_ATTRIBUTE), "Certificate 10" },
    };

    printf("Creating 10 RSA private keys and 10 X.509 certificates...\n");

    for (i = 0; i < 10 && ret == CKR_OK; i++) {
        /* Create RSA private keys */
        printf("Creating %s...\n", rsaTemplates[i].name);
        ret = funcList->C_CreateObject(session, rsaTemplates[i].template,
                                      rsaTemplates[i].count, &obj);
        CHECK_CKR(ret, rsaTemplates[i].name);

        if (ret == CKR_OK && objectCount < 20) {
            createdObjects[objectCount++] = obj;
        }

        /* Create certificates */
        printf("Creating %s...\n", certTemplates[i].name);
        ret = funcList->C_CreateObject(session, certTemplates[i].template,
                                      certTemplates[i].count, &obj);
        CHECK_CKR(ret, certTemplates[i].name);

        if (ret == CKR_OK && objectCount < 20) {
            createdObjects[objectCount++] = obj;
        }
    }

    if (ret == CKR_OK) {
        printf("Successfully created %d objects (10 RSA keys + 10 certificates)\n", objectCount);
        printf("TPM memory consumption test completed successfully.\n");
        printf("Objects will remain in token storage until manually cleaned up.\n");
    } else {
        printf("Failed to create all objects. Created %d objects before failure.\n", objectCount);
    }

    return ret;
}

static CK_RV read_rsa_keys_and_certs(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE template[2];
    CK_ULONG count;
    int i;

    printf("Reading 10 RSA private keys and 10 X.509 certificates...\n");

    /* Read RSA private keys */
    for (i = 0; i < 10 && ret == CKR_OK; i++) {
        printf("Reading RSA Key %d...\n", i + 1);

        /* Find the RSA private key by class and key type */
        template[0].type = CKA_CLASS;
        template[0].pValue = &privKeyClass;
        template[0].ulValueLen = sizeof(privKeyClass);
        template[1].type = CKA_KEY_TYPE;
        template[1].pValue = &rsaKeyType;
        template[1].ulValueLen = sizeof(rsaKeyType);

        ret = funcList->C_FindObjectsInit(session, template, 2);
        CHECK_CKR(ret, "FindObjectsInit for RSA key");

        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &obj, 1, &count);
            CHECK_CKR(ret, "FindObjects for RSA key");

            if (ret == CKR_OK && count > 0) {
                /* Read key attributes to verify it's accessible */
                CK_ATTRIBUTE readTemplate[3];
                CK_BBOOL decrypt, sign;

                readTemplate[0].type = CKA_DECRYPT;
                readTemplate[0].pValue = &decrypt;
                readTemplate[0].ulValueLen = sizeof(decrypt);
                readTemplate[1].type = CKA_SIGN;
                readTemplate[1].pValue = &sign;
                readTemplate[1].ulValueLen = sizeof(sign);
                readTemplate[2].type = CKA_MODULUS;
                readTemplate[2].pValue = NULL;
                readTemplate[2].ulValueLen = 0;

                ret = funcList->C_GetAttributeValue(session, obj, readTemplate, 3);
                CHECK_CKR(ret, "GetAttributeValue for RSA key");

                if (ret == CKR_OK) {
                    printf("  RSA Key %d: DECRYPT=%s, SIGN=%s, MODULUS_LEN=%lu\n",
                           i + 1,
                           decrypt ? "TRUE" : "FALSE",
                           sign ? "TRUE" : "FALSE",
                           readTemplate[2].ulValueLen);
                }
            } else {
                printf("  RSA Key %d: Not found\n", i + 1);
                ret = CKR_OBJECT_HANDLE_INVALID;
            }

            funcList->C_FindObjectsFinal(session);
        }
    }

    /* Read X.509 certificates */
    for (i = 0; i < 10 && ret == CKR_OK; i++) {
        printf("Reading Certificate %d...\n", i + 1);

        /* Find the certificate by class and certificate type */
        template[0].type = CKA_CLASS;
        template[0].pValue = &certClass;
        template[0].ulValueLen = sizeof(certClass);
        template[1].type = CKA_CERTIFICATE_TYPE;
        template[1].pValue = &x509CertType;
        template[1].ulValueLen = sizeof(x509CertType);

        ret = funcList->C_FindObjectsInit(session, template, 2);
        CHECK_CKR(ret, "FindObjectsInit for certificate");

        if (ret == CKR_OK) {
            ret = funcList->C_FindObjects(session, &obj, 1, &count);
            CHECK_CKR(ret, "FindObjects for certificate");

            if (ret == CKR_OK && count > 0) {
                /* Read certificate attributes to verify it's accessible */
                CK_ATTRIBUTE readTemplate[2];
                CK_BBOOL token;

                readTemplate[0].type = CKA_TOKEN;
                readTemplate[0].pValue = &token;
                readTemplate[0].ulValueLen = sizeof(token);
                readTemplate[1].type = CKA_VALUE;
                readTemplate[1].pValue = NULL;
                readTemplate[1].ulValueLen = 0;

                ret = funcList->C_GetAttributeValue(session, obj, readTemplate, 2);
                CHECK_CKR(ret, "GetAttributeValue for certificate");

                if (ret == CKR_OK) {
                    printf("  Certificate %d: TOKEN=%s, CERT_LEN=%lu\n",
                           i + 1,
                           token ? "TRUE" : "FALSE",
                           readTemplate[1].ulValueLen);
                }
            } else {
                printf("  Certificate %d: Not found\n", i + 1);
                ret = CKR_OBJECT_HANDLE_INVALID;
            }

            funcList->C_FindObjectsFinal(session);
        }
    }

    if (ret == CKR_OK) {
        printf("Successfully read all 20 objects (10 RSA keys + 10 certificates)\n");
    } else {
        printf("Failed to read all objects. Error code: 0x%lx\n", ret);
    }

    return ret;
}

static CK_RV tpm_memory_test(CK_SESSION_HANDLE session)
{
    CK_RV ret = CKR_OK;

    printf("=== TPM Memory Consumption Test ===\n");
    printf("This test creates 10 RSA private keys and 10 X.509 certificates\n");
    printf("using C_CreateObject to test TPM memory consumption.\n\n");

    ret = pkcs11_init(libName, &session);
    if (ret != CKR_OK) {
        printf("Failed to initialize PKCS#11 library\n");
        return ret;
    }

    ret = create_rsa_keys_and_certs(session);

    printf("\nTest Results:\n");
    if (ret == CKR_OK) {
        printf("SUCCESS: All objects created successfully\n");
        printf("Created %d objects total\n", objectCount);
    } else {
        printf("FAILURE: Test failed with error code: 0x%lx\n", ret);
        printf("Created %d objects before failure\n", objectCount);
    }

    pkcs11_final(session);

    if (ret == CKR_OK) {
        printf("re-initializing PKCS#11 library\n");
        ret = pkcs11_init(libName, &session);
        if (ret != CKR_OK) {
            printf("Failed to re-initialize PKCS#11 library\n");
            return ret;
        }

        /* Read the created keys and certificates to verify they are accessible */
        printf("\n=== Reading Created Objects ===\n");
        ret = read_rsa_keys_and_certs(session);
        if (ret == CKR_OK) {
            printf("SUCCESS: All objects read successfully\n");
        } else {
            printf("FAILURE: Failed to read objects with error code: 0x%lx\n", ret);
        }

        /* Cleanup objects */
        printf("\nCleaning up created objects...\n");
        cleanup_objects(session);
        printf("Cleanup completed.\n");

        pkcs11_final(session);
    }

    return ret;
}



/* Display the usage options of the test program. */
static void Usage(void)
{
    printf("tpm_memory_test\n");
    printf("-?                 Help, print this usage\n");
    printf("-lib <file>        PKCS#11 library to test\n");
    printf("-slot <num>        Slot number to use\n");
    printf("-userPin <string>  User PIN\n");
    printf("-v                 Verbose output\n");
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int tpm_memory_test_main(int argc, char* argv[])
#endif
{
    int ret;
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store", 1);
    }
#endif

    argc--;
    argv++;
    while (argc > 0) {
        if (string_matches(*argv, "-?")) {
            Usage();
            return 0;
        }
        else if (string_matches(*argv, "-lib")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Library name not supplied\n");
                return 1;
            }
            libName = *argv;
        }
        else if (string_matches(*argv, "-slot")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "Slot number not supplied\n");
                return 1;
            }
            slot = atoi(*argv);
        }
        else if (string_matches(*argv, "-userPin")) {
            argc--;
            argv++;
            if (argc == 0) {
                fprintf(stderr, "User PIN not supplied\n");
                return 1;
            }
            userPin = (byte*)*argv;
        }
        else if (string_matches(*argv, "-v")) {
            verbose = 1;
        }
        else {
            fprintf(stderr, "Unrecognized command line argument\n  %s\n",
                argv[0]);
            return 1;
        }

        argc--;
        argv++;
    }

    userPinLen = (int)XSTRLEN((const char*)userPin);
    soPinLen = (int)XSTRLEN((const char*)soPin);

    rv = tpm_memory_test(session);

    if (rv == CKR_OK)
        ret = 0;
    else
        ret = 1;
    return ret;
}

#else

#ifndef NO_MAIN_DRIVER
int main(int argc, char* argv[])
#else
int tpm_memory_test_main(int argc, char* argv[])
#endif
{
    (void)argc;
    (void)argv;
#ifdef WOLFPKCS11_NO_STORE
    fprintf(stderr, "Store disabled\n");
#else
    fprintf(stderr, "RSA disabled\n");
#endif
    return 0;
}

#endif /* !WOLFPKCS11_NO_STORE && !NO_RSA */