# These CK* values come from the PKCS#11 spec
CKO_CERTIFICATE = 0x1
CKO_PUBLIC_KEY = 0x2
CKO_PRIVATE_KEY = 0x3
CKO_SECRET_KEY = 0x4

CKK_RSA = 0x0
CKK_EC = 0x3
CKK_AES = 0x1f

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0
CKM_RSA_PKCS = 0x1
CKM_RSA_X_509 = 0x3
CKM_RSA_PKCS_OAEP = 0x9
CKM_RSA_PKCS_PSS = 0xD
CKM_AES_CBC = 0x1082
CKM_EC_KEY_PAIR_GEN = 0x1040
CKM_ECDSA = 0x1041
CKM_AES_KEY_GEN = 0x1080

CKM_SHA_1 = 0x220
CKG_MGF1_SHA1 = 0x1
CKM_SHA256 = 0x250
CKG_MGF1_SHA256 = 0x2

CKA_CLASS = 0x0
CKA_TOKEN = 0x1
CKA_PRIVATE = 0x2
CKA_LABEL = 0x3
CKA_VALUE = 0x11
CKA_CERTIFICATE_TYPE = 0x80
CKA_ISSUER = 0x81
CKA_SERIAL_NUMBER = 0x82
CKA_TRUSTED = 0x86
CKA_CERTIFICATE_CATEGORY = 0x87
CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x88
CKA_URL = 0x89
CKA_CHECK_VALUE = 0x90
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x8A
CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x8B
CKA_NAME_HASH_ALGORITHM = 0x8C
CKA_KEY_TYPE = 0x100
CKA_SUBJECT = 0x101
CKA_ID = 0x102
CKA_SENSITIVE = 0x103
CKA_ENCRYPT = 0x104
CKA_DECRYPT = 0x105
CKA_WRAP = 0x106
CKA_UNWRAP = 0x107
CKA_SIGN = 0x108
CKA_SIGN_RECOVER = 0x109
CKA_VERIFY = 0x10A
CKA_VERIFY_RECOVER = 0x10B
CKA_DERIVE = 0x10C
CKA_START_DATE = 0x110
CKA_END_DATE = 0x111
CKA_MODULUS = 0x120
CKA_MODULUS_BITS = 0x121
CKA_PUBLIC_EXPONENT = 0x122
CKA_PUBLIC_KEY_INFO = 0x129
CKA_VALUE_LEN = 0x161
CKA_EXTRACTABLE = 0x162
CKA_LOCAL = 0x163
CKA_NEVER_EXTRACTABLE = 0x164
CKA_ALWAYS_SENSITIVE = 0x165
CKA_KEY_GEN_MECHANISM = 0x166
CKA_MODIFIABLE = 0x170
CKA_COPYABLE = 0x171
CKA_DESTROYABLE = 0x172
CKA_EC_PARAMS = 0x180
CKA_EC_POINT = 0x181
CKA_ALWAYS_AUTHENTICATE = 0x202
CKA_WRAP_WITH_TRUSTED = 0x210
CKA_WRAP_TEMPLATE=0x40000211
CKA_UNWRAP_TEMPLATE=0x40000212
CKA_ALLOWED_MECHANISMS=0x40000600

CKC_X_509 = 0

CK_SECURITY_DOMAIN_UNSPECIFIED = 0x0

CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0x0
