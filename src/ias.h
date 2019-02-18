
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

#include "sscep.h"

PKCS7_ISSUER_AND_SUBJECT *d2i_PKCS7_ISSUER_AND_SUBJECT_bio(BIO *bp, PKCS7_ISSUER_AND_SUBJECT **p7);

int i2d_PKCS7_ISSUER_AND_SUBJECT_bio(BIO *bp, PKCS7_ISSUER_AND_SUBJECT *p7);

DECLARE_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SUBJECT)

int i2d_PKCS7_ISSUER_AND_SERIAL_bio(BIO *bp, PKCS7_ISSUER_AND_SERIAL *p7);
