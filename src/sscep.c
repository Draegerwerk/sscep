/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Main routine */

#define HTTP_CMP "http://"
#define HTTPS_CMP "https://"

#include "sscep.h"

// Global variables
int operation_flag;

// Program name
char *pname;

// Network timeout
int timeout;

// Certificates, requests, keys..
X509 *cacert;
X509 *encert;
X509 *localcert;
X509 *othercert;
X509 *renewal_cert;
X509_REQ *request;
EVP_PKEY *rsa;
EVP_PKEY *renewal_key;
X509_CRL *crl;
FILE *cafile;
FILE *reqfile;
FILE *otherfile;
FILE *crlfile;

/* Fingerprint, signing and encryption algorithms */
EVP_MD *fp_alg;
EVP_MD *sig_alg;
EVP_CIPHER *enc_alg;

/* OpenSSL OID handles */
int nid_messageType;
int nid_pkiStatus;
int nid_failInfo;
int nid_senderNonce;
int nid_recipientNonce;
int nid_transId;
int nid_extensionReq;

/* Global pkistatus */
int pkistatus;

static char *handle_serial(char *serial) {
    int hex = NULL != strchr(serial, ':');

    /* Convert serial to a decimal serial when input is
       a hexidecimal representation of the serial */
    if (hex) {
        unsigned int i, ii;
        char *tmp_serial = (char *) calloc(strlen(serial) + 1, 1);

        for (i = 0, ii = 0; '\0' != serial[i]; i++) {
            if (':' != serial[i])
                tmp_serial[ii++] = serial[i];
        }
        serial = tmp_serial;
    } else {
        unsigned int i;
        for (i = 0; !hex && '\0' != serial[i]; i++)
            hex = 'a' == serial[i] || 'b' == serial[i] || 
                  'c' == serial[i] || 'd' == serial[i] || 
                  'e' == serial[i] || 'f' == serial[i];
    }

    if (hex) {
        ASN1_INTEGER *ai;
        BIGNUM *ret;
        BIO *in = BIO_new_mem_buf(serial, -1);
        char buf[1025];
        ai = ASN1_INTEGER_new();
        if (ai == NULL) return NULL;
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            return NULL;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            return NULL;
        } else {
            serial = BN_bn2dec(ret);
        }
    }

    return serial;
} /* handle_serial */

int main(int argc, char **argv) {
    //ENGINE *e = NULL;
    int c, host_port = 80, count = 1;
    char *host_name, *p, *dir_name = NULL;
    char http_string[16384];
    struct http_reply reply;
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];
    struct scep scep_t = {0};
    FILE *fp = NULL;
    BIO *bp;
    STACK_OF(X509) *nextcara = NULL;
    X509 *cert = NULL;
    PKCS7 p7;
    int i;
    int required_option_space;


#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD( 2, 2 );

    err = WSAStartup( wVersionRequested, &wsaData );
    if ( err != 0 ) {
      // Tell the user that we could not find a usable
      // WinSock DLL.
      return;
    }

    // Confirm that the WinSock DLL supports 2.2.
    // Note that if the DLL supports versions greater than 2.2 in addition to
    // 2.2, it will still return 2.2 in wVersion since that is the version we
    // requested.
    if ( LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 2 ) {
        // Tell the user that we could not find a usable
        // WinSock DLL.
        WSACleanup( );
        return;
    }

#endif
    // Initialize scep layer
    init_scep();

    // Set program name
    pname = argv[0];

    // Set timeout
    timeout = TIMEOUT;

    // Check operation parameter
    if (!argv[1]) {
        usage();
    } else if (!strncmp(argv[1], "getca", 5)) {
        operation_flag = SCEP_OPERATION_GETCA;
    } else if (!strncmp(argv[1], "enroll", 6)) {
        operation_flag = SCEP_OPERATION_ENROLL;
    } else if (!strncmp(argv[1], "getcert", 7)) {
        operation_flag = SCEP_OPERATION_GETCERT;
    } else if (!strncmp(argv[1], "getcrl", 6)) {
        operation_flag = SCEP_OPERATION_GETCRL;
    } else if (!strncmp(argv[1], "getnextca", 9)) {
        operation_flag = SCEP_OPERATION_GETNEXTCA;
    } else {
        log_error("missing or illegal operation parameter");
        usage();
    }
    // Skip first parameter and parse the rest of the command
    optind++;
    while ((c = getopt(argc, argv, "c:C:de:E:f:g:hF:i:k:K:l:L:n:O:p:r:Rs:S:t:T:u:vw:m:HM:")) != -1)
        switch (c) {
            case 'c':
                c_flag = 1;
                c_char = optarg;
                break;
            case 'C':
                C_flag = 1;
                C_char = optarg;
                break;
            case 'd':
                log_set_level(LOG_TRACE);
                d_flag = 1;
                break;
            case 'e':
                e_flag = 1;
                e_char = optarg;
                break;
            case 'E':
                E_flag = 1;
                E_char = optarg;
                break;
            case 'F':
                F_flag = 1;
                F_char = optarg;
                break;
            case 'f':
                f_flag = 1;
                f_char = optarg;
                break;
            case 'g':
                g_flag = 1;
                g_char = optarg;
                break;
            case 'h':
                // TODO: change to eg. ID --inform=ID
                h_flag = 1;
                break;
            case 'H':
                H_flag = 1;
                break;
            case 'i':
                i_flag = 1;
                i_char = optarg;
                break;
            case 'k':
                k_flag = 1;
                k_char = optarg;
                break;
            case 'K':
                K_flag = 1;
                K_char = optarg;
                break;
            case 'l':
                l_flag = 1;
                l_char = optarg;
                break;
            case 'L':
                L_flag = 1;
                L_char = optarg;
                break;
            case 'm':
                m_flag = 1;
                m_char = optarg;
                break;
            case 'M':
                if (!M_flag) {
                    /* if this is the first time the option appears, create a
                     * new string.
                     */
                    required_option_space = strlen(optarg) + 1;
                    M_char = malloc(required_option_space);
                    if (!M_char)
                        error_memory();
                    strncpy(M_char, optarg, required_option_space);
                    // set the flag, so we already have a string
                    M_flag = 1;
                } else {
                    /* we already have a string, just extend it. */
                    // old part + new part + &-sign + null byte
                    required_option_space = strlen(M_char) + strlen(optarg) + 2;
                    M_char = realloc(M_char, required_option_space);
                    if (!M_char)
                        error_memory();
                    strncat(M_char, "&", 1);
                    strncat(M_char, optarg, strlen(optarg));
                }
                break;
            case 'n':
                n_flag = 1;
                n_num = atoi(optarg);
                break;
            case 'O':
                O_flag = 1;
                O_char = optarg;
                break;
            case 'p':
                p_flag = 1;
                p_char = optarg;
                break;
            case 'r':
                r_flag = 1;
                r_char = optarg;
                break;
            case 'R':
                R_flag = 1;
                break;
            case 's':
                s_flag = 1;
                /*s_char = optarg;*/
                s_char = handle_serial(optarg);
                break;
            case 'S':
                S_flag = 1;
                S_char = optarg;
                break;
            case 't':
                t_flag = 1;
                t_num = atoi(optarg);
                break;
            case 'T':
                T_flag = 1;
                T_num = atoi(optarg);
                break;
            case 'u':
                u_flag = 1;
                url_char = optarg;
                break;
            case 'v':
                log_set_level(LOG_DEBUG);
                v_flag = 1;
                break;
            case 'w':
                w_flag = 1;
                w_char = optarg;
                break;
            default:
                log_error("unrecognized parameter: %s\n", argv[optind]);
                usage();
        }
    argc -= optind;
    argv += optind;

    // If we debug, include verbose messages also
    if (d_flag)
        v_flag = 1;

    if (f_char) {
        scep_conf_init(f_char);
    } else {
        scep_conf = NULL;    //moved init to here otherwise compile error on windows
    }
    // Read in the configuration file:
    /*if (f_char) {
        if (fopen_s(&fp, f_char, "r"))
            log_error("cannot open %s", f_char);
        else {
            init_config(fp);
            (void)fclose(fp);
        }
    }*/
    log_debug("starting sscep, version %s", VERSION);

    /*
    * Create a new SCEP transaction and self-signed
    * certificate based on cert request
    */
    log_debug("new transaction");
    new_transaction(&scep_t);

    /*enable Engine Support */
    if (g_flag) {
        scep_t.e = scep_engine_init(scep_t.e);
    }

    /*
     * Check argument logic.
     */
    if (!c_flag) {
        if (operation_flag == SCEP_OPERATION_GETCA) {
            log_error("missing CA certificate filename (-c)");
            exit(SCEP_PKISTATUS_ERROR);
        } else {
            log_error("missing CA certificate (-c)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
            log_error("missing nextCA certificate target filename (-c)");
            exit(SCEP_PKISTATUS_ERROR);
        } else {
            log_error("missing nextCA certificate target filename(-c)");
            exit(SCEP_PKISTATUS_ERROR);
        }
    }
    if (!C_flag) {
        if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
            log_error("missing nextCA certificate chain filename (-C)");
            exit(SCEP_PKISTATUS_ERROR);
        }
    }
    if (operation_flag == SCEP_OPERATION_ENROLL) {
        if (!K_flag) {
            if (!k_flag) {
                log_error("missing private key for self-signed cert creation (-k) or (-K and -O)");
                exit(SCEP_PKISTATUS_ERROR);
            }
        }
        if (!r_flag) {
            log_error("missing request (-r)");
            exit(SCEP_PKISTATUS_ERROR);

        }
        if (!l_flag) {
            log_error("missing local cert (-l)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        /* Set polling limits */
        if (!n_flag)
            n_num = MAX_POLL_COUNT;
        if (!t_flag)
            t_num = POLL_TIME;
        if (!T_flag)
            T_num = MAX_POLL_TIME;
    }
    if (operation_flag == SCEP_OPERATION_GETCERT) {
        if (!l_flag) {
            log_error("missing local cert (-l)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (!s_flag) {
            log_error("missing serial no (-s)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (!w_flag) {
            log_error("missing cert file (-w)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (!k_flag) {
            log_error("missing private key (-k)");
            exit(SCEP_PKISTATUS_ERROR);
        }
    }
    if (operation_flag == SCEP_OPERATION_GETCRL) {
        if (!l_flag) {
            log_error("missing local cert (-l)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (!w_flag) {
            log_error("missing crl file (-w)");
            exit(SCEP_PKISTATUS_ERROR);
        }
        if (!k_flag) {
            log_error("missing private key (-k)");
            exit(SCEP_PKISTATUS_ERROR);
        }
    }

    /* Break down the URL */
    if (!u_flag) {
        log_error("missing URL (-u)");
        exit(SCEP_PKISTATUS_ERROR);
    }
    int url_head_len = 0;
    if (!p_flag) {
        if(strncmp(url_char, HTTP_CMP, strlen(HTTP_CMP)) == 0) {
            ssl_flag = 0;
            url_head_len = (int) strlen(HTTP_CMP);
        } else if(strncmp(url_char, HTTPS_CMP, strlen(HTTPS_CMP)) == 0) {
            ssl_flag = 1;
            host_port = 443;
            url_head_len = (int) strlen(HTTPS_CMP);
        } else {
            log_error("illegal URL %s", url_char);
            exit(SCEP_PKISTATUS_ERROR);
        }
    }
    if (p_flag) {
#ifdef WIN32
        host_name = _strdup(p_char);
#else
        host_name = strdup(p_char);
#endif
        dir_name = url_char;
    }

#ifdef WIN32
    else if (!(host_name = _strdup(url_char + url_head_len)))
#else
    else if (!(host_name = strdup(url_char + url_head_len)))
#endif
        error_memory();

    p = host_name;
    c = 0;
    while (*p != '\0') {
        if (*p == '/' && !p_flag && !c) {
            *p = '\0';
            if (*(p + 1)) dir_name = p + 1;
            else dir_name = "";
            c = 1;
        }
        if (*p == ':') {
            *p = '\0';
            if (*(p + 1)) host_port = atoi(p + 1);
        }
        p++;
    }
    if (!dir_name) {
        log_error("illegal URL %s", url_char);
        exit(SCEP_PKISTATUS_ERROR);
    }
    if (host_port < 1 || host_port > 65550) {
        log_error("illegal port number %d", host_port);
        exit(SCEP_PKISTATUS_ERROR);
    }

    log_debug("hostname: %s", host_name);
    log_debug("directory: %s", dir_name);
    log_debug("port: %d", host_port);

    /* Check algorithms */
    if (!E_flag) {
        enc_alg = (EVP_CIPHER *) EVP_des_cbc();
    } else if (!strncmp(E_char, "blowfish", 8)) {
        enc_alg = (EVP_CIPHER *) EVP_bf_cbc();
    } else if (!strncmp(E_char, "des", 3)) {
        enc_alg = (EVP_CIPHER *) EVP_des_cbc();
    } else if (!strncmp(E_char, "3des", 4)) {
        enc_alg = (EVP_CIPHER *) EVP_des_ede3_cbc();
    } else if (!strncmp(E_char, "aes", 3)) {
        enc_alg = (EVP_CIPHER *) EVP_aes_256_cbc();
    } else {
        log_error("unsupported algorithm: %s", E_char);
        exit(SCEP_PKISTATUS_ERROR);
    }
    if (!S_flag) {
        sig_alg = (EVP_MD *) EVP_md5();
    } else if (!strncmp(S_char, "md5", 3)) {
        sig_alg = (EVP_MD *) EVP_md5();
    } else if (!strncmp(S_char, "sha1", 4)) {
        sig_alg = (EVP_MD *) EVP_sha1();
    } else if (!strncmp(S_char, "sha256", 6)) {
        sig_alg = (EVP_MD *)EVP_sha256();
    } else if (!strncmp(S_char, "sha512", 6)) {
        sig_alg = (EVP_MD *)EVP_sha512();
    } else {
        log_error("unsupported algorithm: %s", S_char);
        exit(SCEP_PKISTATUS_ERROR);
    }
    /* Fingerprint algorithm */
    if (!F_flag) {
        fp_alg = (EVP_MD *) EVP_md5();
    } else if (!strncmp(F_char, "md5", 3)) {
        fp_alg = (EVP_MD *) EVP_md5();
    } else if (!strncmp(F_char, "sha1", 4)) {
        fp_alg = (EVP_MD *) EVP_sha1();
    } else if (!strncmp(F_char, "sha256", 6)) {
        fp_alg = (EVP_MD *)EVP_sha256();
    } else if (!strncmp(F_char, "sha512", 6)) {
        fp_alg = (EVP_MD *)EVP_sha512();
    } else {
        log_error("unsupported algorithm: %s", F_char);
        exit(SCEP_PKISTATUS_ERROR);
    }

    /*
     * Switch to operation specific code
     */
    switch (operation_flag) {
        case SCEP_OPERATION_GETCA:
            log_debug("SCEP_OPERATION_GETCA");

            /* Set CA identifier */
            if (!i_flag)
                i_char = CA_IDENTIFIER;

            /* Forge the HTTP message */

            if (!M_flag) {
                snprintf(http_string, sizeof(http_string),
                         "GET %s%s?operation=GetCACert&message=%s "
                         "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
                         i_char);

            } else {
                snprintf(http_string, sizeof(http_string),
                         "GET %s%s?operation=GetCACert&message=%s&%s "
                         "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
                         i_char, M_char);

            }

            log_trace("requesting CA certificate\nscep msg: %s", http_string);

            /*
             * Send http message.
             * Response is written to http_response struct "reply".
             */
            reply.payload = NULL;
           if ((c = send_msg(&reply, http_string, host_name,
                              host_port, operation_flag)) == 1) {
                log_error("error while sending message");
                exit(SCEP_PKISTATUS_NET);
            }
            if (reply.payload == NULL) {
                log_error("no data, perhaps you should define CA identifier (-i)");
                exit(SCEP_PKISTATUS_SUCCESS);
            }
            log_debug("valid response from server");
            if (reply.type == SCEP_MIME_GETCA_RA) {
                /* XXXXXXXXXXXXXXXXXXXXX chain not verified */
                write_ca_ra(&reply);
            }
            /* Read payload as DER X.509 object: */
            bp = BIO_new_mem_buf(reply.payload, reply.bytes);
            cacert = d2i_X509_bio(bp, NULL);

            /* Read and print certificate information */
            if (!X509_digest(cacert, fp_alg, md, &n)) {
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_ERROR);
            }
            if (v_flag) {
                log_debug("%s fingerprint: ", OBJ_nid2sn(EVP_MD_type(fp_alg)));
                for (c = 0; c < (int) n; c++) {
                    log_debug("%02X%c", md[c], (c + 1 == (int) n) ? '\n' : ':');
                }
            }

            // Write PEM-formatted file:
            if (fopen_s(&fp, c_char , "w")) {
                log_error("cannot open CA file for writing");
                exit(SCEP_PKISTATUS_ERROR);
            }
            if (PEM_write_X509(fp, cacert) != 1) {
                log_error("error while writing CA file");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_ERROR);
            }
            log_debug("CA certificate written as %s", c_char);
            fclose(fp);
            scep_t.pki_status = pkistatus = SCEP_PKISTATUS_SUCCESS;
            break;

        case SCEP_OPERATION_GETNEXTCA:
            log_debug("SCEP_OPERATION_GETNEXTCA");

            /* Set CA identifier */
            if (!i_flag)
                i_char = CA_IDENTIFIER;

            /* Forge the HTTP message */
            if (!M_flag) {
                snprintf(http_string, sizeof(http_string),
                         "GET %s%s?operation=GetNextCACert&message=%s "
                         "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
                         i_char);

            } else {
                snprintf(http_string, sizeof(http_string),
                         "GET %s%s?operation=GetNextCACert&message=%s&%s "
                         "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
                         i_char, M_char);

            }

            log_trace("requesting nextCA certificate\nscep msg: %s", http_string);

            /*
             * Send http message.
             * Response is written to http_response struct "reply".
             */
            reply.payload = NULL;
            if ((c = send_msg(&reply, http_string, host_name, host_port, operation_flag)) == 1) {
                log_error("error while sending message; getnextCA might be not available");
                exit(SCEP_PKISTATUS_NET);
            }
            if (reply.payload == NULL) {
                log_error("no data, perhaps you there is no nextCA available");
                exit(SCEP_PKISTATUS_SUCCESS);
            }
            log_trace("valid response from server");

            if (reply.type == SCEP_MIME_GETNEXTCA) {
                /* XXXXXXXXXXXXXXXXXXXXX chain not verified */

                //write_ca_ra(&reply);

                /* Set the whole struct as 0 */
                memset(&scep_t, 0, sizeof(scep_t));

                scep_t.reply_payload = reply.payload;
                scep_t.reply_len = reply.bytes;
                scep_t.request_type = SCEP_MIME_GETNEXTCA; 
                pkcs7_verify_unwrap(&scep_t, C_char);

                //pkcs7_unwrap(&scep_t);
            }


            /* Get certs */
            p7 = *(scep_t.reply_p7);
            nextcara = scep_t.reply_p7->d.sign->cert;

            log_debug("verify and unwrap: found %d cert(s)", sk_X509_num(nextcara));

            for (i = 0; i < sk_X509_num(nextcara); i++) {
                char buffer[1024];
                char name[1024];
                memset(buffer, 0, 1024);
                memset(name, 0, 1024);

                cert = sk_X509_value(nextcara, i);
                if (v_flag) {
                    log_debug("found certificate with\n subject: '%s'\n issuer: %s",
                           X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer)),
                           X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer)));
                }

                /* Create name */
                snprintf(name, 1024, "%s-%d", c_char, i);


                /* Write PEM-formatted file: */
                if (!(fp = fopen(name, "w"))) {
                    log_error("cannot open cert file for writing");
                    exit(SCEP_PKISTATUS_FILE);
                }

                log_debug("writing cert");
                if (d_flag) PEM_write_X509(stdout, cert);

                if (PEM_write_X509(fp, cert) != 1) {
                    log_error("error while writing certificate file");
                    ERR_print_errors_fp(stderr);
                    exit(SCEP_PKISTATUS_FILE);
                }
                log_debug("certificate written as %s", name);
                fclose(fp);
            }

            pkistatus = SCEP_PKISTATUS_SUCCESS;
            break;

        case SCEP_OPERATION_GETCERT:
        case SCEP_OPERATION_GETCRL:
            /* Read local certificate */
            if (!l_flag) {
                log_error("missing local cert (-l)");
                exit(SCEP_PKISTATUS_FILE);
            }
            read_cert(&localcert, l_char);

        case SCEP_OPERATION_ENROLL:
            /*
             * Read in CA cert, private key and certificate
             * request in global variables.
             */

            if (c_flag) {
                log_trace("read CA cert: %s", c_char);
                read_cert(&cacert, c_char);
            } else {
                log_error("missing CA cert (-c)");
                exit (SCEP_PKISTATUS_FILE);
            }
            if (e_flag) {
                log_trace("read encryption cert: %s", e_char);
                read_cert(&encert, e_char);
            }

            if (!K_flag) {
                if (scep_conf != NULL) {
                    sscep_engine_read_key_new(&rsa, k_char, scep_t.e);
                } else {
                    read_key(&rsa, k_char);
                }
            }

            if ((K_flag && !O_flag) || (!K_flag && O_flag)) {
                log_error("-O also requires -K (and vice-versa)");
                exit(SCEP_PKISTATUS_FILE);
            } else if (K_flag && O_flag) {
                //TODO auf hwcrhk prüfen?
                if (scep_conf != NULL) {
                    sscep_engine_read_key_old(&renewal_key, K_char, scep_t.e);
                } else {
                    read_key(&renewal_key, K_char);
                }
                read_cert(&renewal_cert, O_char);
            }

            if (operation_flag == SCEP_OPERATION_ENROLL) {
                if (r_flag) read_request(&request, r_char);
                else log_warn("missing request file parameter (-r)");
                scep_t.transaction_id = key_fingerprint(request);
                log_debug("Read request with transaction id: %s", scep_t.transaction_id);
            }

            if (operation_flag != SCEP_OPERATION_ENROLL)
                goto not_enroll;

            if (!O_flag) {
                log_debug("generating selfsigned certificate");
                new_selfsigned(&scep_t);
            } else {
                /* Use existing certificate */
                scep_t.signercert = renewal_cert;
                scep_t.signerkey = renewal_key;
            }

            // Write the selfsigned certificate if requested
            if (L_flag) {
                write_cert(scep_t.signercert, L_char);
            }
            // Write issuer name and subject (GetCertInitial):
            if (!(scep_t.ias_getcertinit->subject = X509_REQ_get_subject_name(request))) {
                log_error("error getting subject for GetCertInitial");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_ERROR);
            }
        not_enroll:
            if (!(scep_t.ias_getcertinit->issuer = X509_get_subject_name(cacert))) {
                log_error("error getting issuer for GetCertInitial");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_ERROR);
            }
            // Write issuer name and serial (GETC{ert,rl}):
            scep_t.ias_getcert->issuer = scep_t.ias_getcertinit->issuer;
            scep_t.ias_getcrl->issuer = scep_t.ias_getcertinit->issuer;
            if (!(scep_t.ias_getcrl->serial = X509_get_serialNumber(cacert))) {
                log_error("error getting serial for GetCertInitial");
                ERR_print_errors_fp(stderr);
                exit(SCEP_PKISTATUS_ERROR);
            }
            // User supplied serial number
            if (s_flag) {
                BIGNUM *bn;
                ASN1_INTEGER *ai;
                int len = BN_dec2bn(&bn, s_char);
                if (!len || !(ai = BN_to_ASN1_INTEGER(bn, NULL))) {
                    log_error("error converting serial");
                    ERR_print_errors_fp(stderr);
                    exit(SCEP_PKISTATUS_SS);
                }
                scep_t.ias_getcert->serial = ai;
            }
            break;
    }

    switch (operation_flag) {
        case SCEP_OPERATION_ENROLL:
            log_debug("SCEP_OPERATION_ENROLL");
            // Resum mode: set GetCertInitial
            if (R_flag) {
                if (n_num == 0) exit(SCEP_PKISTATUS_SUCCESS);
                log_info("requesting certificate (#1)");
                scep_t.request_type = SCEP_REQUEST_GETCERTINIT;
                count++;
            } else {
                log_info("sending certificate request");
                scep_t.request_type = SCEP_REQUEST_PKCSREQ;
            }
            break;

        case SCEP_OPERATION_GETCERT:
            log_debug("SCEP_OPERATION_GETCERT");
            scep_t.request_type = SCEP_REQUEST_GETCERT;
            log_info("requesting certificate");
            break;

        case SCEP_OPERATION_GETCRL:
            log_debug("SCEP_OPERATION_GETCRL");
            scep_t.request_type = SCEP_REQUEST_GETCRL;
            log_info("requesting crl");
            break;
    }

    // Enter polling loop
    while (scep_t.pki_status != SCEP_PKISTATUS_SUCCESS) {
        // create payload
        pkcs7_wrap(&scep_t);

        // URL-encode
        p = url_encode((char *) scep_t.request_payload, scep_t.request_len);

        // Test mode print SCEP request and don't send it
        if (m_flag) {
            // Write output file :
            if ((fopen_s(&fp, m_char, "w"))) {
                log_error("cannot open output file for writing (%s)", m_char);
            } else {
                log_info("writing PEM fomatted PKCS#7");
                PEM_write_PKCS7(fp, scep_t.request_p7);
            }
            return 0;
        }

        // Forge the HTTP message
        /* snprintf(http_string, sizeof(http_string),
                "GET %s%s?operation="
                "PKIOperation&message="
                "%s HTTP/1.0\r\n\r\n",
                p_flag ? "" : "/", dir_name, p);*/

        if (!M_flag) {
            snprintf(http_string, sizeof(http_string),
                     "GET %s%s?operation=PKIOperation&message=%s "
                     "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name, p);
        } else {
            snprintf(http_string, sizeof(http_string),
                     "GET %s%s?operation=PKIOperation&message=%s&%s "
                     "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name, p, M_char);
        }

        log_trace("scep msg: %s", http_string);

        // send http
        reply.payload = NULL;
        if ((c = send_msg(&reply, http_string, host_name, host_port, operation_flag)) == 1) {
            log_error("error while sending message");
            exit(SCEP_PKISTATUS_NET);
        }
        // Verisign Onsite returns strange reply... XXXXXXXXXXXXXXXXXXX
        if ((reply.status == 200) && (reply.payload == NULL)) {
            /*
            scep_t.pki_status = SCEP_PKISTATUS_PENDING;
            break;
            */
            exit(SCEP_PKISTATUS_ERROR);
        }
        log_info("valid response from server\n");

        // Check payload
        scep_t.reply_len = reply.bytes;
        scep_t.reply_payload = (unsigned char *) reply.payload;
        pkcs7_unwrap(&scep_t);
        pkistatus = scep_t.pki_status;

        switch (scep_t.pki_status) {
            case SCEP_PKISTATUS_SUCCESS:
                break;
            case SCEP_PKISTATUS_PENDING:
                // Check time limits
                if (((t_num * count) >= T_num) || (count > n_num)) {
                    exit(pkistatus);
                }
                scep_t.request_type = SCEP_REQUEST_GETCERTINIT;

                // Wait for poll interval
                log_debug("waiting for %d secs", t_num);
                sleep(t_num);
                log_info("requesting certificate (#%d)", count);

                // Add counter
                count++;
                break;

            case SCEP_PKISTATUS_FAILURE:

                // Handle failure
                switch (scep_t.fail_info) {
                    case SCEP_FAILINFO_BADALG:
                        exit(SCEP_PKISTATUS_BADALG);
                    case SCEP_FAILINFO_BADMSGCHK:
                        exit(SCEP_PKISTATUS_BADMSGCHK);
                    case SCEP_FAILINFO_BADREQ:
                        exit(SCEP_PKISTATUS_BADREQ);
                    case SCEP_FAILINFO_BADTIME:
                        exit(SCEP_PKISTATUS_BADTIME);
                    case SCEP_FAILINFO_BADCERTID:
                        exit(SCEP_PKISTATUS_BADCERTID);
                        // Shouldn't be there...
                    default:
                        exit(SCEP_PKISTATUS_ERROR);
                }
            default:
                log_error("unknown pkiStatus");
                exit(SCEP_PKISTATUS_ERROR);
        }
    }
    // We got SUCCESS, analyze the reply
    switch (scep_t.request_type) {

        // Local certificate
        case SCEP_REQUEST_PKCSREQ:
        case SCEP_REQUEST_GETCERTINIT:
            write_local_cert(&scep_t);
            break;

            // Other end entity certificate
        case SCEP_REQUEST_GETCERT:
            write_other_cert(&scep_t);
            break;
            // CRL
        case SCEP_REQUEST_GETCRL:
            write_crl(&scep_t);
            break;
    }
    // TODO: right location for the disable ??
//    if(e){
//        ENGINE_finish(*e);
//        ENGINE_free(*e);
//        hwEngine = NULL;
//        ENGINE_cleanup();
//    }
    return (pkistatus);
}

void usage() {
    fprintf(stdout, "\nsscep version %s\n\n", VERSION);
    fprintf(stdout, "Usage: %s OPERATION [OPTIONS]\n"
                    "\nAvailable OPERATIONs are\n"
                    "  getca             Get CA/RA certificate(s)\n"
                    "  getnextca         Get next CA/RA certificate(s)\n"
                    "  enroll            Enroll certificate\n"
                    "  getcert           Query certificate\n"
                    "  getcrl            Query CRL\n"
                    "\nGeneral OPTIONS\n"
                    "  -u <url>          SCEP server URL\n"
                    "  -p <host:port>    Use proxy server at host:port\n"
                    "  -M <string>         Monitor Information String name=value&name=value ...\n"
                    "  -g                Enable Engine support\n"
                    "  -h                 Keyforme=ID. \n" // TODO
                    "  -f <file>         Use configuration file\n"
                    "  -c <file>         CA certificate file (write if OPERATION is getca or getnextca)\n"
                    "  -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish|aes)\n"
                    "  -S <name>         PKCS#7 signature algorithm (md5|sha1|sha256|sha512)\n"
                    "  -v                Verbose operation\n"
                    "  -d                Debug (even more verbose operation)\n"
                    "\nOPTIONS for OPERATION getca are\n"
                    "  -i <string>       CA identifier string\n"
    "  -F <name>         Fingerprint algorithm (md5|sha1|sha256|sha512)\n"
                    "\nOPTIONS for OPERATION getnextca are\n"
                    "  -C <file>         Local certificate chain file for signature verification in PEM format \n"
                    "  -F <name>         Fingerprint algorithm\n"
                    "  -c <file>         CA certificate file (write if OPERATION is getca or getnextca)\n"
                    "  -w <file>         Write signer certificate in file (optional) \n"
                    "\nOPTIONS for OPERATION enroll are\n"
                    "  -k <file>         Private key file\n"
                    "  -r <file>         Certificate request file\n"
                    "  -K <file>         Signature private key file, use with -O\n"
                    "  -O <file>         Signature certificate (used instead of self-signed)\n"
                    "  -l <file>         Write enrolled certificate in file\n"
                    "  -e <file>         Use different CA cert for encryption\n"
                    "  -L <file>         Write selfsigned certificate in file\n"
                    "  -t <secs>         Polling interval in seconds\n"
                    "  -T <secs>         Max polling time in seconds\n"
                    "  -n <count>        Max number of GetCertInitial requests\n"
                    "  -R                Resume interrupted enrollment\n"
                    "\nOPTIONS for OPERATION getcert are\n"
                    "  -k <file>         Private key file\n"
                    "  -l <file>         Local certificate file\n"
                    "  -s <number>       Certificate serial number\n"
                    "  -w <file>         Write certificate in file\n"
                    "\nOPTIONS for OPERATION getcrl are\n"
                    "  -k <file>         Private key file\n"
                    "  -l <file>         Local certificate file\n"
                    "  -w <file>         Write CRL in file\n\n", pname);
    exit(0);
}

void catchalarm(int signo) {
    fprintf(stderr, "%s: connection timed out\n", pname);
    exit(SCEP_PKISTATUS_TIMEOUT);
}
