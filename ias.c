
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/*
 * Routines for pkcs7_issuer_and_subject data type needed when
 * sending GETCertInitial requests.
 */

#include "sscep.h"
#include "ias.h"


ASN1_NDEF_SEQUENCE(PKCS7_ISSUER_AND_SUBJECT) = {
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, issuer, X509_NAME),
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, subject, X509_NAME)
} ASN1_NDEF_SEQUENCE_END(PKCS7_ISSUER_AND_SUBJECT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SUBJECT)


PKCS7_ISSUER_AND_SUBJECT *d2i_PKCS7_ISSUER_AND_SUBJECT_bio(BIO *bp, PKCS7_ISSUER_AND_SUBJECT **p7)
{
   return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SUBJECT), bp, p7);
}

int i2d_PKCS7_ISSUER_AND_SUBJECT_bio(BIO *bp, PKCS7_ISSUER_AND_SUBJECT *p7)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SUBJECT), bp, p7);
}


PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL_bio(BIO *bp, PKCS7_ISSUER_AND_SERIAL **p7)
{
   return ASN1_item_d2i_bio(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SERIAL), bp, p7);
}

int i2d_PKCS7_ISSUER_AND_SERIAL_bio(BIO *bp, PKCS7_ISSUER_AND_SERIAL *p7)
{
    return ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS7_ISSUER_AND_SERIAL), bp, p7);
}

