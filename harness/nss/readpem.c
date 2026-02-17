/* 
 * NSS does not handle external ML-KEM keys yet.
 * replicate the NSS raw key structure so we can parse
 * PEM key. In the future, we can use the NSS builtin
 * functions to import a key from raw pem data. For now
 * this function only handles ml-kem keys */
#include <seccomon.h>
#include <pk11pub.h>
#include <keythi.h>
#include <keyhi.h>
#include <nssb64.h>

struct seckeyKyberPrivateKeyStr {
    KyberParams params;
    SECItem privateValue;
    SECItem seed;
};
typedef struct seckeyKyberPrivateKeyStr seckeyKyberPrivateKey;

/*
** raw private key object
*/
struct seckeyRawPrivateKeyStr {
    PLArenaPool *arena;
    KeyType keyType;
    union {
        seckeyKyberPrivateKey kyber;
    } u;
};
typedef struct seckeyRawPrivateKeyStr seckeyRawPrivateKey;

SEC_ASN1_MKSUB(SEC_OctetStringTemplate)

/* ASN1 Templates for new decoder/encoder */
/*
 * Attribute value for PKCS8 entries (static?)
 */
const SEC_ASN1Template seckey_AttributeTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(SECKEYAttribute) },
    { SEC_ASN1_OBJECT_ID, offsetof(SECKEYAttribute, attrType) },
    { SEC_ASN1_SET_OF | SEC_ASN1_XTRN, offsetof(SECKEYAttribute, attrValue),
      SEC_ASN1_SUB(SEC_AnyTemplate) },
    { 0 }
};

const SEC_ASN1Template seckey_SetOfAttributeTemplate[] = {
    { SEC_ASN1_SET_OF, 0, seckey_AttributeTemplate },
};

const SEC_ASN1Template seckey_PrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SECKEYPrivateKeyInfo) },
    { SEC_ASN1_INTEGER, offsetof(SECKEYPrivateKeyInfo, version) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN,
      offsetof(SECKEYPrivateKeyInfo, algorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_OCTET_STRING, offsetof(SECKEYPrivateKeyInfo, privateKey) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(SECKEYPrivateKeyInfo, attributes),
      seckey_SetOfAttributeTemplate },
    { 0 }
};

const SEC_ASN1Template seckey_PointerToPrivateKeyInfoTemplate[] = {
    { SEC_ASN1_POINTER, 0, seckey_PrivateKeyInfoTemplate }
};

const SEC_ASN1Template seckey_MLKEMPrivateKeyBothExportTemplate[] = {
    { SEC_ASN1_CHOICE, 0, NULL, sizeof(seckeyRawPrivateKey) },
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(seckeyRawPrivateKey) },
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.kyber.seed) },
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.kyber.privateValue) },
    { 0 }
};

const SEC_ASN1Template seckey_MLKEMPrivateKeySeedExportTemplate[] = {
    { SEC_ASN1_CHOICE, 0, NULL, sizeof(seckeyRawPrivateKey) },
    { SEC_ASN1_CONTEXT_SPECIFIC | 0,
      offsetof(seckeyRawPrivateKey, u.kyber.seed),
      SEC_ASN1_SUB(SEC_OctetStringTemplate) },
    { 0 }
};

const SEC_ASN1Template seckey_MLKEMPrivateKeyKeyExportTemplate[] = {
    { SEC_ASN1_CHOICE, 0, NULL, sizeof(seckeyRawPrivateKey) },
    { SEC_ASN1_OCTET_STRING, offsetof(seckeyRawPrivateKey, u.kyber.privateValue) },
    { 0 }
};


#define USGOV 0x60, 0x86, 0x48, 0x01, 0x65
#define NISTALGS USGOV, 3, 4
#define KEMS NISTALGS, 4

unsigned char oid_value_ml_kem_768[] = { KEMS, 2 };
unsigned char oid_value_ml_kem_1024[] = { KEMS, 3 };

SECItem oid_item_ml_kem_768 = { siBuffer, oid_value_ml_kem_768,
                                sizeof(oid_value_ml_kem_768) };
SECItem oid_item_ml_kem_1024 = { siBuffer, oid_value_ml_kem_1024,
                                sizeof(oid_value_ml_kem_1024) };

SECOidData oid_data_ml_kem_768 = {
    { siBuffer, oid_value_ml_kem_768, sizeof(oid_value_ml_kem_768) },
    SEC_OID_UNKNOWN, "ML-KEM-768", CKM_ML_KEM, INVALID_CERT_EXTENSION,
};

SECOidData oid_data_ml_kem_1024 = {
    { siBuffer, oid_value_ml_kem_1024, sizeof(oid_value_ml_kem_1024) },
    SEC_OID_UNKNOWN, "ML-KEM-1024", CKM_ML_KEM, INVALID_CERT_EXTENSION,
};

CK_ML_KEM_PARAMETER_SET_TYPE
get_MLKEMParamSet(KyberParams params)
{
    switch (params) {
    case params_ml_kem768:
    case params_ml_kem768_test_mode:
        return CKP_ML_KEM_768;
    case params_ml_kem1024:
    case params_ml_kem1024_test_mode:
        return CKP_ML_KEM_1024;
    default:
        break;
    }
    return (CK_ULONG)-1UL;
}

KyberParams
KyberParamsAlgTag(SECOidTag algTag)
{
    SECOidTag oid_ml_kem_768 = SEC_OID_UNKNOWN;
    SECOidTag oid_ml_kem_1024 = SEC_OID_UNKNOWN;

    oid_ml_kem_768 = SECOID_AddEntry(&oid_data_ml_kem_768);
    oid_ml_kem_1024 = SECOID_AddEntry(&oid_data_ml_kem_1024);
    if (oid_ml_kem_768 == algTag) {
        return params_ml_kem768;
    }
    if (oid_ml_kem_1024 == algTag) {
        return params_ml_kem1024;
    }
    return params_kyber_invalid;
}

SECKEYPrivateKey *
pk11_MakePrivKey(PK11SlotInfo *slot, KeyType keyType,
                 PRBool isTemp, CK_OBJECT_HANDLE privID, void *wincx)
{
    PLArenaPool *arena;
    SECKEYPrivateKey *privKey;
    PRBool isPrivate;
    SECStatus rv;

    /* now we need to create space for the private key */
    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL)
        return NULL;

    privKey = (SECKEYPrivateKey *)
        PORT_ArenaZAlloc(arena, sizeof(SECKEYPrivateKey));
    if (privKey == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
        return NULL;
    }

    privKey->arena = arena;
    privKey->keyType = keyType;
    privKey->pkcs11Slot = PK11_ReferenceSlot(slot);
    privKey->pkcs11ID = privID;
    privKey->pkcs11IsTemp = isTemp;
    privKey->wincx = wincx;

    return privKey;
}

#define PK11_SETATTRS(x, id, v, l) \
    (x)->type = (id);              \
    (x)->pValue = (v);             \
    (x)->ulValueLen = (l);

SECStatus
pk11_ImportAndReturnPrivateKey(PK11SlotInfo *slot, seckeyRawPrivateKey *lpk,
                               SECItem *nickname, PRBool isPrivate,
                               unsigned int keyUsage,
                               SECKEYPrivateKey **privk,
                               void *wincx)
{
    CK_BBOOL cktrue = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_OBJECT_HANDLE objectID;
    CK_ATTRIBUTE theTemplate[20];
    int templateCount = 0;
    SECStatus rv = SECFailure;
    CK_ATTRIBUTE *attrs;
    CK_ATTRIBUTE *signedattr = NULL;
    int signedcount = 0;
    CK_ATTRIBUTE *ap;
    SECItem *ck_id = NULL;
    CK_ULONG paramSet;
    PK11GenericObject *genObj = NULL;

    attrs = theTemplate;

    PK11_SETATTRS(attrs, CKA_CLASS, &keyClass, sizeof(keyClass));
    attrs++;
    PK11_SETATTRS(attrs, CKA_KEY_TYPE, &keyType, sizeof(keyType));
    attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN, &ckfalse, sizeof(CK_BBOOL));
    attrs++;
    PK11_SETATTRS(attrs, CKA_SENSITIVE, isPrivate ? &cktrue : &ckfalse,
                  sizeof(CK_BBOOL));
    attrs++;
    PK11_SETATTRS(attrs, CKA_PRIVATE, isPrivate ? &cktrue : &ckfalse,
                  sizeof(CK_BBOOL));
    attrs++;

    switch (lpk->keyType) {
        case kyberKey:
            keyType = CKK_ML_KEM;
            /* currently we don't deal with seed in nss softoken */
            if ((lpk->u.kyber.privateValue.len == 0)) {
                PORT_SetError(SEC_ERROR_BAD_KEY);
                goto loser;
            }
            PK11_SETATTRS(attrs, CKA_DECAPSULATE, &cktrue, sizeof(CK_BBOOL));
            attrs++;
            if (nickname) {
                PK11_SETATTRS(attrs, CKA_LABEL, nickname->data, nickname->len);
                attrs++;
            }
            paramSet = get_MLKEMParamSet(lpk->u.kyber.params);
            PK11_SETATTRS(attrs, CKA_PARAMETER_SET, (unsigned char *)&paramSet,
                          sizeof(CK_ML_KEM_PARAMETER_SET_TYPE));
            attrs++;
            PK11_SETATTRS(attrs, CKA_VALUE, lpk->u.kyber.privateValue.data,
                          lpk->u.kyber.privateValue.len);
            attrs++;
            break;
        default:
            PORT_SetError(SEC_ERROR_BAD_KEY);
            goto loser;
    }
    templateCount = attrs - theTemplate;
    PORT_Assert(templateCount <= sizeof(theTemplate) / sizeof(CK_ATTRIBUTE));

    genObj = PK11_CreateGenericObject(slot, theTemplate,
                                      templateCount, PR_FALSE);
    if (genObj) { rv = SECSuccess; }
    /* create and return a SECKEYPrivateKey */
    if (genObj !=NULL && privk != NULL) {
        objectID = PK11_GetObjectHandle(PK11_TypeGeneric, genObj, NULL);
        *privk = pk11_MakePrivKey(slot, lpk->keyType, PR_TRUE, objectID, wincx);
        if (*privk == NULL) {
            rv = SECFailure;
        }
    }
loser:
    if (genObj) {
        PK11_DestroyGenericObject(genObj);
    }
    return rv;
}


SECStatus
pk11_ImportPrivateKeyInfoAndReturnKey(PK11SlotInfo *slot,
                                      SECKEYPrivateKeyInfo *pki,
                                      SECItem *nickname,
                                      PRBool isPrivate, unsigned int keyUsage,
                                      SECKEYPrivateKey **privk, void *wincx)
{
    SECStatus rv = SECFailure;
    seckeyRawPrivateKey *lpk = NULL;
    const SEC_ASN1Template *keyTemplate, *paramTemplate;
    void *paramDest = NULL;
    PLArenaPool *arena = NULL;
    SECOidTag algTag;
    SECOidTag oid_ml_kem_768 = SEC_OID_UNKNOWN;
    SECOidTag oid_ml_kem_1024 = SEC_OID_UNKNOWN;

    oid_ml_kem_768 = SECOID_AddEntry(&oid_data_ml_kem_768);
    oid_ml_kem_1024 = SECOID_AddEntry(&oid_data_ml_kem_1024);

    arena = PORT_NewArena(2048);
    if (!arena) {
        return SECFailure;
    }

    /* need to change this to use RSA/DSA keys */
    lpk = (seckeyRawPrivateKey *)PORT_ArenaZAlloc(arena,
                                                  sizeof(seckeyRawPrivateKey));
    if (lpk == NULL) {
        goto loser;
    }
    lpk->arena = arena;

    algTag = SECOID_GetAlgorithmTag(&pki->algorithm);
    if ((algTag == oid_ml_kem_768) || (algTag == oid_ml_kem_1024)) {
        if (pki->privateKey.data == NULL || pki->privateKey.len == 0) {
            PORT_SetError(SEC_ERROR_BAD_KEY);
            goto loser;
        }
        /* choice */
        switch (pki->privateKey.data[0]) {
            case SEC_ASN1_CONTEXT_SPECIFIC | 0:
                keyTemplate = seckey_MLKEMPrivateKeySeedExportTemplate;
                break;
            case SEC_ASN1_OCTET_STRING:
                keyTemplate = seckey_MLKEMPrivateKeyKeyExportTemplate;
                break;
            case SEC_ASN1_CONSTRUCTED | SEC_ASN1_SEQUENCE:
                keyTemplate = seckey_MLKEMPrivateKeyBothExportTemplate;
                break;
            default:
                keyTemplate = NULL;
                PORT_SetError(SEC_ERROR_BAD_DER);
                break;
        }
        paramTemplate = NULL;
        paramDest = NULL;
        lpk->keyType = kyberKey;
        lpk->u.kyber.params = KyberParamsAlgTag(algTag);
    }

    if (!keyTemplate) {
        goto loser;
    }

    /* decode the private key and any algorithm parameters */
    rv = SEC_QuickDERDecodeItem(arena, lpk, keyTemplate, &pki->privateKey);
    if (rv != SECSuccess) {
        goto loser;
    }

    if (paramDest && paramTemplate) {
        rv = SEC_ASN1DecodeItem(arena, paramDest, paramTemplate,
                                &(pki->algorithm.parameters));
        if (rv != SECSuccess) {
            goto loser;
        }
    }

    rv = pk11_ImportAndReturnPrivateKey(slot, lpk, nickname, isPrivate,
                                        keyUsage, privk, wincx);
loser:
    if (arena != NULL) {
        PORT_FreeArena(arena, PR_TRUE);
    }

    return rv;
}

SECStatus
pk11_ImportDERPrivateKeyInfoAndReturnKey(PK11SlotInfo *slot, SECItem *derPKI,
                                         SECItem *nickname,
                                         PRBool isPrivate,
                                         unsigned int keyUsage,
                                         SECKEYPrivateKey **privk,
                                         void *wincx)
{
    SECKEYPrivateKeyInfo *pki = NULL;
    PLArenaPool *temparena = NULL;
    SECStatus rv = SECFailure;

    temparena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (!temparena) {
        return rv;
    }

    pki = PORT_ArenaZNew(temparena, SECKEYPrivateKeyInfo);
    if (!pki) {
        PORT_FreeArena(temparena, PR_FALSE);
        return rv;
    }
    pki->arena = temparena;

    rv = SEC_ASN1DecodeItem(pki->arena, pki, seckey_PrivateKeyInfoTemplate,
                            derPKI);
    if (rv != SECSuccess) {
        /* If SEC_ASN1DecodeItem fails, we cannot assume anything about the
         * validity of the data in pki. The best we can do is free the arena
         * and return. */
        PORT_FreeArena(temparena, PR_TRUE);
        return rv;
    }
    if (pki->privateKey.data == NULL || pki->privateKey.len == 0) {
        /* If SEC_ASN1DecodeItems succeeds but SECKEYPrivateKeyInfo.privateKey
         * is a zero-length octet string, free the arena and return a failure
         * to avoid trying to zero the corresponding SECItem in
         * SECKEY_DestroyPrivateKeyInfo(). */
        PORT_FreeArena(temparena, PR_TRUE);
        PORT_SetError(SEC_ERROR_BAD_KEY);
        return SECFailure;
    }

    rv = pk11_ImportPrivateKeyInfoAndReturnKey(slot, pki, nickname, isPrivate,
                                               keyUsage, privk, wincx);

    /* this zeroes the key and frees the arena */
    SECKEY_DestroyPrivateKeyInfo(pki, PR_TRUE /*freeit*/);
    return rv;
}

#define PRIV_KEY_LABEL "-----BEGIN PRIVATE KEY-----"
char *get_DERPKI(FILE *fp)
{
    size_t len;
    size_t start, end;
    char *buf1, *buf2;
    size_t i, ret;
    /* get the full size */
    fseek(fp, 0L, SEEK_END);
    len = ftell(fp);
    buf1 = PORT_Alloc(len+1);
    if (buf1 == NULL) {
        return NULL;
    }
    rewind(fp);
    ret = fread(buf1, 1, len, fp);
    if (ret != len) {
        PORT_Free(buf1);
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return NULL;
    }
    buf1[len] = 0;
    for(i=0; i < len; i++ ) {
        if (buf1[i] == '-') {
            if (PORT_Strncmp(&buf1[i], PRIV_KEY_LABEL,
                sizeof(PRIV_KEY_LABEL)-1) == 0) {
                i += sizeof(PRIV_KEY_LABEL)-1;
               break;
            }
        }
    }
    if (i >= len) {
        PORT_Free(buf1);
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return NULL;
    }
    start = i;
    for (;i < len; i++ ) {
        if (buf1[i] == '-') {
            break;
        }
    }
    end =  i;
    len = end - start;
    buf2 = PORT_Alloc(len);
    PORT_Memcpy(buf2, &buf1[start], len);
    buf2[len] = 0;
    PORT_Free(buf1);
    return buf2;
}

/* read a pem file and return a SECKEYPrivateKey */
SECKEYPrivateKey *
read_PrivateKey(FILE *fp)
{
    SECKEYPrivateKey *privkey = NULL;
    char *asciiDerPKI = NULL;
    SECItem derPKI = {siBuffer, NULL, 0};
    SECItem *item = NULL;
    PK11SlotInfo *slot = NULL;
    SECStatus rv;

    slot = PK11_GetInternalSlot();
    if (slot == NULL) {
        goto loser;
    }
    /* read pem data */
    asciiDerPKI = get_DERPKI(fp);
    if (asciiDerPKI == NULL) {
        goto loser;
    }
    item = NSSBase64_DecodeBuffer(NULL, &derPKI, asciiDerPKI,
                                  PORT_Strlen(asciiDerPKI));
    if (item == NULL) {
        goto loser;
    }
    rv = pk11_ImportDERPrivateKeyInfoAndReturnKey(slot, &derPKI, NULL,
                                                  PR_FALSE, KU_ALL,
                                                  &privkey, NULL);
    if (rv != SECSuccess) {
        goto loser;
    }

    PK11_FreeSlot(slot);
    PORT_Free(derPKI.data);
    PORT_Free(asciiDerPKI);
    return privkey;
loser:
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (derPKI.data) {
        PORT_Free(derPKI.data);
    }
    if (asciiDerPKI) {
        PORT_Free(asciiDerPKI);
    }
    return NULL;
}
