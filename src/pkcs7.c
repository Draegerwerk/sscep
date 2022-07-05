/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* PKCS#7 routines */

#include "sscep.h"
#include "ias.h"
#include <openssl/x509.h>

#define X509_ATTRIBUTE_STACK STACK_OF(X509_ATTRIBUTE)
/*
 * Wrap data in PKCS#7 envelopes and base64-encode the result.
 * Data is PKCS#10 request in PKCSReq, or pkcs7_issuer_and_subject
 * structure in GetCertInitial and PKCS7_ISSUER_AND_SERIAL in
 * GetCert and GETCrl.
 */
int pkcs7_wrap(struct scep *s) {
    BIO                     *databio = NULL;
    BIO                     *encbio = NULL;
    BIO                     *pkcs7bio = NULL;
    BIO                     *memorybio = NULL;
    BIO                     *outbio = NULL;
    BIO                     *base64bio = NULL;
    unsigned char           *buffer = NULL;
    int                     rc, len = 0, i=0;
    STACK_OF(X509)          *recipients;
    PKCS7                   *p7enc;
    PKCS7_SIGNER_INFO       *si;
    X509_ATTRIBUTE_STACK    *attributes;
    X509                    *signercert = NULL;
    EVP_PKEY                *signerkey = NULL;
    X509_REQ                *reqcsr = NULL;

    // Create a new sender nonce for all messages XXXXXXXXXXXXXX should it be per transaction?
    s->sender_nonce_len = 16;
    s->sender_nonce = malloc(s->sender_nonce_len);
    RAND_bytes(s->sender_nonce, s->sender_nonce_len);

    // Prepare data payload
    switch(s->request_type) {
        case SCEP_REQUEST_PKCSREQ:
            // Set printable message type
            // We set this later as an autheticated attribute "messageType".
            s->request_type_str = SCEP_REQUEST_PKCSREQ_STR;

            // Signer cert
            signercert = s->signercert;
            signerkey = s->signerkey;

            // Create inner PKCS#7
            log_debug("creating inner PKCS#7");

            // Read request in memory bio
            databio = BIO_new(BIO_s_mem());
            if ((rc = i2d_X509_REQ_bio(databio, request)) <= 0) {
                log_error("error writing certificate request in bio");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_P7);
            } else {
                log_debug("inner PKCS#7 in mem BIO");
            }
            break;

        case SCEP_REQUEST_GETCERTINIT:

            // Set printable message type
            s->request_type_str = SCEP_REQUEST_GETCERTINIT_STR;

            // Signer cert
            signercert = s->signercert;
            signerkey = s->signerkey;

            // Create inner PKCS#7
            log_debug("creating inner PKCS#7");

            // Read data in memory bio
            databio = BIO_new(BIO_s_mem());
            if ((rc = i2d_PKCS7_ISSUER_AND_SUBJECT_bio(databio, s->ias_getcertinit)) <= 0) {
                log_error("error writing GetCertInitial data in bio");
                ERR_print_errors_fp(stderr);
                exit (SCEP_PKISTATUS_P7);
            }
            break;

        case SCEP_REQUEST_GETCERT:
            // Set printable message type
            s->request_type_str = SCEP_REQUEST_GETCERT_STR;

            // Signer cert
            signercert = localcert;
            signerkey = rsa;

            // Read data in memory bio
            databio = BIO_new(BIO_s_mem());
            if ((rc = i2d_PKCS7_ISSUER_AND_SERIAL_bio(databio, s->ias_getcert)) <= 0) {
                log_error("error writing GetCert data in bio");
                ERR_print_errors_fp(stderr);
                exit (SCEP_PKISTATUS_P7);
            }
            break;

        case SCEP_REQUEST_GETCRL:
            // Set printable message type
            s->request_type_str = SCEP_REQUEST_GETCRL_STR;

            // Signer cert
            signercert = localcert;
            signerkey = rsa;

            // Read data in memory bio
            databio = BIO_new(BIO_s_mem());
            if ((rc = i2d_PKCS7_ISSUER_AND_SERIAL_bio(databio, s->ias_getcrl)) <= 0) {
                log_error("error writing GetCert data in bio\n");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_P7);
            }

            break;
    }

    if( BIO_flush(databio) <= 0 ){
        log_error("error flushing databio");
    }
    BIO_set_flags(databio, BIO_FLAGS_MEM_RDONLY);

    // Below this is the common code for all request_type

    // Read in the payload
    s->request_len = BIO_get_mem_data(databio, &s->request_payload);
    if (v_flag){
        log_debug("request data dump");
        PEM_write_X509_REQ(stdout, request);
    }

    log_debug("data payload size: %d bytes", s->request_len);

    // Create encryption certificate stack
    if ((recipients = sk_X509_new(NULL)) == NULL) {
        log_error("error creating certificate stack");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    // Use different CA cert for encryption if requested
    if (e_flag) {
        if (sk_X509_push(recipients, encert) <= 0) {
            log_error("error adding recipient encryption certificate");
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }
    } else {
        // Use same CA cert also for encryption
        if (sk_X509_push(recipients, cacert) <= 0) {
            log_error("error adding recipient encryption certificate");
            ERR_print_errors_fp(stderr);
            exit (SCEP_PKISTATUS_P7);
        }
    }

    // Create BIO for encryption
    if (d_flag){
        log_trace("hexdump request payload", i);
        for(i=0; i < s->request_len; i++ ) {
            fprintf(stdout, "%02x ", s->request_payload[i]);
            if ((i + 1) % 8 == 0) fprintf(stdout, " ");
            if ((i + 1) % 16 == 0) fprintf(stdout, "\n");
        }
        fprintf(stdout, "\n");
    }
    log_trace("hexdump payload %d", i);

    if ((encbio = BIO_new_mem_buf(s->request_payload, s->request_len)) == NULL) {
        log_error("error creating data bio");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    // Encrypt
    if (!(p7enc = PKCS7_encrypt(recipients, encbio, enc_alg, PKCS7_BINARY))) {
        log_error("request payload encrypt failed");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("successfully encrypted payload");

    // Write encrypted data
    memorybio = BIO_new(BIO_s_mem());
    if (i2d_PKCS7_bio(memorybio, p7enc) <= 0) {
        log_error("error writing encrypted data");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    BIO_flush(memorybio);
    BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
    len = BIO_get_mem_data(memorybio, &buffer);
    log_debug("envelope size: %d bytes", len);
    if (d_flag) {
        log_trace("printing PEM formatted PKCS#7");
        PEM_write_PKCS7(stdout, p7enc);
    }
    BIO_free(memorybio);

    // Create outer PKCS#7
    log_debug("creating outer PKCS#7");
    s->request_p7 = PKCS7_new();
    if (s->request_p7 == NULL) {
        log_error("failed creating PKCS#7 for signing");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }
    if (!PKCS7_set_type(s->request_p7, NID_pkcs7_signed)) {
        log_error("failed setting PKCS#7 type");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }

    // Add signer certificate and signature
    PKCS7_add_certificate(s->request_p7, signercert);
    if ((si = PKCS7_add_signature(s->request_p7, signercert, signerkey, sig_alg)) == NULL) {
        log_error("error adding PKCS#7 signature");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }
    log_debug("signature added successfully");

    // Set signed attributes
    log_debug("adding signed attributes");
    attributes = sk_X509_ATTRIBUTE_new_null();
    add_attribute_string(attributes, nid_transId, s->transaction_id);
    add_attribute_string(attributes, nid_messageType, s->request_type_str);
    add_attribute_octet(attributes, nid_senderNonce, s->sender_nonce, s->sender_nonce_len);
    PKCS7_set_signed_attributes(si, attributes);

    // Add contentType
    if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data))) {
        log_error("error adding NID_pkcs9_contentType");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }

    // Create new content
    if (!PKCS7_content_new(s->request_p7, NID_pkcs7_data)) {
        log_error("failed setting PKCS#7 content type");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }

    // Write data
    pkcs7bio = PKCS7_dataInit(s->request_p7, NULL);
    if (pkcs7bio == NULL) {
        log_error("error opening bio for writing PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }
    if (len != BIO_write(pkcs7bio, buffer, len)) {
        log_error("error writing PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }
    log_debug("PKCS#7 data written successfully");

    // Finalize PKCS#7
    if (!PKCS7_dataFinal(s->request_p7, pkcs7bio)) {
        log_error("error finalizing outer PKCS#7");
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }
    if (d_flag) {
        log_trace("printing PEM fomatted PKCS#7");
        PEM_write_PKCS7(stdout, s->request_p7);
    }

    // base64-encode the data
    log_debug("applying base64 encoding");

    // Create base64 filtering bio
    memorybio = BIO_new(BIO_s_mem());
    base64bio = BIO_new(BIO_f_base64());
    outbio = BIO_push(base64bio, memorybio);

    // Copy PKCS#7
    i2d_PKCS7_bio(outbio, s->request_p7);
    BIO_flush(outbio);
    BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
    s->request_len = BIO_get_mem_data(memorybio, &s->request_payload);
    log_debug("base64 encoded payload size: %d bytes", s->request_len);
    BIO_free(outbio);
    BIO_free(databio);
    return (0);
}


int pkcs7_verify_unwrap(struct scep *s , char * cachainfile ) {
    BIO                *memorybio;
    BIO                *outbio;
    BIO                *pkcs7bio;
    int                i, len, bytes, used;
    STACK_OF(PKCS7_SIGNER_INFO)    *sk;
    PKCS7                *p7;
    PKCS7_SIGNER_INFO        *si;
    X509_ATTRIBUTE_STACK        *attribs;
    char                *p;
    unsigned char            buffer[1024];
    X509                *recipientcert;
    EVP_PKEY            *recipientkey;
    X509                   *signercert;
    FILE                 *fp;

    X509_STORE_CTX         *cert_ctx;

    X509_STORE *cert_store=NULL;


    /* Create new memory BIO for outer PKCS#7 */
    memorybio = BIO_new(BIO_s_mem());

    /* Read in data */
    log_debug("reading outer PKCS#7");
    if ((len = BIO_write(memorybio, s->reply_payload, s->reply_len)) <= 0) {
        log_error("error reading PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("PKCS#7 payload size: %d bytes", len);
    BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
    s->reply_p7 = d2i_PKCS7_bio(memorybio, NULL);
    if (d_flag) {
        log_trace("printing PEM fomatted PKCS#7");
        PEM_write_PKCS7(stdout, s->reply_p7);
    }

     // Make sure this is a signed PKCS#7
    if (!PKCS7_type_is_signed(s->reply_p7)) {
        log_error("PKCS#7 is not signed!");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    // Create BIO for content data
    pkcs7bio = PKCS7_dataInit(s->reply_p7, NULL);
    if (pkcs7bio == NULL) {
        log_error("cannot get PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    // Copy enveloped data from PKCS#7
    outbio = BIO_new(BIO_s_mem());
    used = 0;
    for (;;) {
        bytes = BIO_read(pkcs7bio, buffer, sizeof(buffer));
        used += bytes;
        if (bytes <= 0) break;
        BIO_write(outbio, buffer, bytes);
    }
    BIO_flush(outbio);
    log_debug("PKCS#7 contains %d bytes of signed data", used);

    // Get signer
    sk = PKCS7_get_signer_info(s->reply_p7);
    if (sk == NULL) {
        log_error("cannot get signer info!\n", pname);
        ERR_print_errors_fp(stderr);
        exit(SCEP_PKISTATUS_P7);
    }

    // Verify signature
    log_debug("verifying signature");
    si = sk_PKCS7_SIGNER_INFO_value(sk, 0);

    signercert = PKCS7_cert_from_signer_info(s->reply_p7, si);
    if(signercert == NULL ) log_info("Can't read signer cert from pkcs7");

    if (PKCS7_signatureVerify(pkcs7bio, s->reply_p7, si,signercert ) <= 0) {
        // reson = ERR_GET_REASON(ERR_peek_last_error());
        log_info("error verifying signature Error");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("signature ok\n");

    // verify certificates
    cert_store=X509_STORE_new();
    if(cert_store == NULL)
        log_error("error verifying certificates");

    X509_STORE_set_flags(cert_store, 0);

    //X509_STORE_load_locations(cert_store,certsfile,certsdir);
    X509_STORE_load_locations(cert_store,cachainfile,NULL);

    if(!(cert_ctx = X509_STORE_CTX_new())) {;
        log_error("error creating certificate chain");
    }

    if(!X509_STORE_CTX_init(cert_ctx,cert_store,signercert,NULL))
    {
        log_error("error verifying certificates");
    }

    //X509_STORE_CTX_set_purpose(cert_ctx, purpose);

    if( !X509_verify_cert(cert_ctx)) {
        log_error("The signer certificate verification failed");
    }

    /*Write pem encoded signer certificate */
    if(w_flag) {
        write_cert(signercert, w_char);
    }
    /* Copy enveloped data into PKCS#7 */
    s->reply_p7 = d2i_PKCS7_bio(outbio, NULL);

    X509_STORE_free(cert_store);
    X509_STORE_CTX_cleanup(cert_ctx);

    return (0);
}


/* Unwrap PKCS#7 data and decrypt if necessary */
int pkcs7_unwrap(struct scep *s) {
    BIO                         *memorybio;
    BIO                         *outbio;
    BIO                         *pkcs7bio;
    int                         i, len, bytes, used;
    STACK_OF(PKCS7_SIGNER_INFO) *sk;
    PKCS7                       *p7enc;
    PKCS7_SIGNER_INFO           *si;
    X509_ATTRIBUTE_STACK        *attribs;
    char                        *p;
    unsigned char               buffer[1024];
    X509                        *recipientcert;
    EVP_PKEY                    *recipientkey;

    /* Create new memory BIO for outer PKCS#7 */
    memorybio = BIO_new(BIO_s_mem());

    /* Read in data */
    log_debug("reading outer PKCS#7");
    if ((len = BIO_write(memorybio, s->reply_payload, s->reply_len)) <= 0) {
        log_error("error reading PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("PKCS#7 payload size: %d bytes", len);
    BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
    s->reply_p7 = d2i_PKCS7_bio(memorybio, NULL);
    if (d_flag) {
        log_trace("printing PEM fomatted PKCS#7");
        PEM_write_PKCS7(stdout, s->reply_p7);
    }

     /* Make sure this is a signed PKCS#7 */
    if (!PKCS7_type_is_signed(s->reply_p7)) {
        log_error("PKCS#7 is not signed!");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Create BIO for content data */
    pkcs7bio = PKCS7_dataInit(s->reply_p7, NULL);
    if (pkcs7bio == NULL) {
        log_error("cannot get PKCS#7 data");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Copy enveloped data from PKCS#7 */
    outbio = BIO_new(BIO_s_mem());
    used = 0;
    while (1) {
        bytes = BIO_read(pkcs7bio, buffer, sizeof(buffer));
        used += bytes;
        if (bytes <= 0) break;
        BIO_write(outbio, buffer, bytes);
    }
    BIO_flush(outbio);

    log_debug("PKCS#7 contains %d bytes of enveloped data", used);

    /* Get signer */
    sk = PKCS7_get_signer_info(s->reply_p7);
    if (sk == NULL) {
        log_error("cannot get signer info!");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Verify signature */
    log_debug("verifying signature\n");
    si = sk_PKCS7_SIGNER_INFO_value(sk, 0);
    if (PKCS7_signatureVerify(pkcs7bio, s->reply_p7, si, cacert) <= 0) {
        log_error("error verifying signature");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("signature ok");

    /* Get signed attributes */
    log_debug("finding signed attributes");
    attribs = PKCS7_get_signed_attributes(si);
    if (attribs == NULL) {
        log_error("no attributes found");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }

    /* Transaction id */
    if ((get_signed_attribute(si, nid_transId, V_ASN1_PRINTABLESTRING, &p)) == 1) {
        log_error("cannot find transId");
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("reply transaction id: %s", p);
    if (strncmp(s->transaction_id, p, strlen(p))) {
        log_error("transaction id mismatch");
        exit (SCEP_PKISTATUS_P7);
    }
    // Message type, should be of type CertRep
    if ((i = get_signed_attribute(si, nid_messageType, V_ASN1_PRINTABLESTRING, &p)) == 1) {
        log_error("cannot find messageType");
        exit (SCEP_PKISTATUS_P7);
    }
    if (atoi(p) != 3) {
        log_error("wrong message type in reply");
        exit (SCEP_PKISTATUS_P7);
    }
    log_debug("reply message type is good");

    // Sender and recipient nonces:
    if ((i = get_signed_attribute(si, nid_senderNonce, V_ASN1_OCTET_STRING, &p)) == 1) {
        log_error("cannot find senderNonce");
        // Some implementations don't put in on reply XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        //exit (SCEP_PKISTATUS_P7);
    }
    s->reply_sender_nonce = p;
    if (v_flag) {
        char nonce[64];
        for (i = 0; i < 16; i++) {
            snprintf(nonce+ (i*2), sizeof(nonce) - (i*2), "%02X", s->reply_sender_nonce[i]);
        }
        log_debug("senderNonce in reply: %s", nonce);
    }
    if (( i = get_signed_attribute(si, nid_recipientNonce, V_ASN1_OCTET_STRING, &p)) == 1) {
        log_error("cannot find recipientNonce");
        exit (SCEP_PKISTATUS_P7);
    }
    s->reply_recipient_nonce = p;
    if (v_flag) {
        char nonce[64];
        for (i = 0; i < 16; i++) {
            snprintf(nonce + (i*2), sizeof(nonce) - (i*2), "%02X", s->reply_recipient_nonce[i]);
        }
        log_debug("recipientNonce in reply: %s", nonce);
    }
    // Compare recipient nonce to original sender nonce
    // The draft says nothing about this, but it makes sense to me..
    // XXXXXXXXXXXXXX check
    for (i = 0; i < 16; i++) {
        if (s->sender_nonce[i] != s->reply_recipient_nonce[i]) {
            log_debug("corrupted nonce received");
            // Instead of exit, break out
            break;
        }
    }
    // Get pkiStatus
    if ((i = get_signed_attribute(si, nid_pkiStatus, V_ASN1_PRINTABLESTRING, &p)) == 1) {
        log_error("cannot find pkiStatus");
        // This is a mandatory attribute..
        exit (SCEP_PKISTATUS_P7);
    }
    switch (atoi(p)) {
        case SCEP_PKISTATUS_SUCCESS:
            log_info("pkistatus: SUCCESS");
            s->pki_status = SCEP_PKISTATUS_SUCCESS;
            break;
        case SCEP_PKISTATUS_FAILURE:
            log_info("pkistatus: FAILURE");
            s->pki_status = SCEP_PKISTATUS_FAILURE;
            break;
        case SCEP_PKISTATUS_PENDING:
            log_info("pkistatus: PENDING");
            s->pki_status = SCEP_PKISTATUS_PENDING;
            break;
        default:
            log_info("wrong pkistatus in reply");
            exit (SCEP_PKISTATUS_P7);
    }

    // Get failInfo
    if (s->pki_status == SCEP_PKISTATUS_FAILURE) {
        if ((i = get_signed_attribute(si, nid_failInfo, V_ASN1_PRINTABLESTRING, &p)) == 1) {
                log_error("cannot find failInfo");
                exit (SCEP_PKISTATUS_P7);
        }
        switch (atoi(p)) {
            case SCEP_FAILINFO_BADALG:
                s->fail_info = SCEP_FAILINFO_BADALG;
                log_info("reason: %s", SCEP_FAILINFO_BADALG_STR);
                break;
            case SCEP_FAILINFO_BADMSGCHK:
                s->fail_info = SCEP_FAILINFO_BADMSGCHK;
                log_info("reason: %s", SCEP_FAILINFO_BADMSGCHK_STR);
                break;
            case SCEP_FAILINFO_BADREQ:
                s->fail_info = SCEP_FAILINFO_BADREQ;
                log_info("reason: %s", SCEP_FAILINFO_BADREQ_STR);
                break;
            case SCEP_FAILINFO_BADTIME:
                s->fail_info = SCEP_FAILINFO_BADTIME;
                log_info("reason: %s", SCEP_FAILINFO_BADTIME_STR);
                break;
            case SCEP_FAILINFO_BADCERTID:
                s->fail_info = SCEP_FAILINFO_BADCERTID;
                log_info("reason: %s", SCEP_FAILINFO_BADCERTID_STR);
                break;
            default:
                log_error("wrong failInfo in reply");
        }
        if ((i = get_signed_attribute(si, nid_failInfo, V_ASN1_PRINTABLESTRING, &p)) == 1) {
            log_error("cannot find failInfo");
            exit (SCEP_PKISTATUS_P7);
        }
        exit (SCEP_PKISTATUS_P7);
    }
    // If FAILURE or PENDING, we can return
    if (s->pki_status != SCEP_PKISTATUS_SUCCESS) {
        // There shouldn't be any more data...
        if (used != 0) {
            log_error("illegal size of payload");
        }
        return (0);
    }
    // We got success and expect data
    if (used == 0) {
        log_error("illegal size of payload");
        exit (SCEP_PKISTATUS_P7);
    }

    // Decrypt the inner PKCS#7
    if ((s->request_type == SCEP_REQUEST_PKCSREQ) || (s->request_type == SCEP_REQUEST_GETCERTINIT)) {
        recipientcert = s->signercert;
        recipientkey = s->signerkey;
    } else {
        recipientcert = localcert;
        recipientkey = rsa;
    }
    log_debug("reading inner PKCS#7");
    p7enc = d2i_PKCS7_bio(outbio, NULL);
    if (p7enc == NULL) {
        log_error("cannot read inner PKCS#7");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    if (d_flag) {
        log_trace("printing PEM fomatted PKCS#7");
        PEM_write_PKCS7(stdout, p7enc);
    }

    /* Decrypt the data  */
    outbio = BIO_new(BIO_s_mem());
    log_debug("decrypting inner PKCS#7");
    if (PKCS7_decrypt(p7enc, recipientkey, recipientcert, outbio, 0) == 0) {
        log_error("error decrypting inner PKCS#7");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    BIO_flush(outbio);

    /* Write decrypted data */
    s->reply_len = BIO_get_mem_data(outbio, &s->reply_payload);
    log_debug("PKCS#7 payload size: %d bytes", s->reply_len);
    BIO_set_flags(outbio, BIO_FLAGS_MEM_RDONLY);
    s->reply_p7 = d2i_PKCS7_bio(outbio, NULL);

    return (0);
}

/* Add signed attributes */
int add_attribute_string(X509_ATTRIBUTE_STACK *attrs, int nid, char *buffer){
    ASN1_STRING     *asn1_string = NULL;
    X509_ATTRIBUTE  *x509_a;
    int             c;

    log_debug("adding string attribute %s", OBJ_nid2sn(nid));

    asn1_string = ASN1_STRING_new();
    if ((c = ASN1_STRING_set(asn1_string, buffer, strlen(buffer))) <= 0) {
        log_error("error adding data to ASN.1 string");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_PRINTABLESTRING, asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

int add_attribute_octet (X509_ATTRIBUTE_STACK *attrs, int nid, char *buffer, int len) {
    ASN1_STRING     *asn1_string = NULL;
    X509_ATTRIBUTE  *x509_a;
    int             c;

    log_debug("adding octet attribute %s\n", OBJ_nid2sn(nid));

    asn1_string = ASN1_STRING_new();
    if ((c = ASN1_STRING_set(asn1_string, buffer, len)) <= 0) {
        log_error("error adding data to ASN.1 string");
        ERR_print_errors_fp(stderr);
        exit (SCEP_PKISTATUS_P7);
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_OCTET_STRING, asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

/* Find signed attributes */
int get_signed_attribute (PKCS7_SIGNER_INFO *si, int nid, int type, char **buffer){
    ASN1_TYPE   *asn1_type;
    int         len;

    log_debug("finding attribute %s", OBJ_nid2sn(nid));

    /* Find attribute */
    asn1_type = PKCS7_get_signed_attribute(si, nid);

    if (ASN1_TYPE_get(asn1_type) != type) {
        log_error("wrong ASN.1 type");
        exit (SCEP_PKISTATUS_P7);
    }

    /* Copy data */
    len = ASN1_STRING_length(asn1_type->value.asn1_string);
    if (len <= 0) { return (1); }
    log_debug("allocating %d bytes for attribute", len);
    if (type == V_ASN1_PRINTABLESTRING) {
        *buffer = ( char *)malloc(len + 1);
    } else {
        *buffer = ( char *)malloc(len);
    }
    if (*buffer == NULL) {
        log_error("cannot malloc space for attribute");
        exit (SCEP_PKISTATUS_P7);
    }
    memcpy(*buffer, ASN1_STRING_get0_data(asn1_type->value.asn1_string), len);

    /* Add null terminator if it's a PrintableString */
    if (type == V_ASN1_PRINTABLESTRING) {
        (*buffer)[len] = 0;
        len++;
    }

    return (0);
} 
