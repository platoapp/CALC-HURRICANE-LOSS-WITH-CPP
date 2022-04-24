/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SSLERR_H
# define HEADER_SSLERR_H

# ifndef HEADER_SYMHACKS_H
#  include <openssl/symhacks.h>
# endif

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_SSL_strings(void);

/*
 * SSL function codes.
 */
# define SSL_F_ADD_CLIENT_KEY_SHARE_EXT                   438
# define SSL_F_ADD_KEY_SHARE                              512
# define SSL_F_BYTES_TO_CIPHER_LIST                       519
# define SSL_F_CHECK_SUITEB_CIPHER_LIST                   331
# define SSL_F_CIPHERSUITE_CB                             622
# define SSL_F_CONSTRUCT_CA_NAMES                         552
# define SSL_F_CONSTRUCT_KEY_EXCHANGE_TBS                 553
# define SSL_F_CONSTRUCT_STATEFUL_TICKET                  636
# define SSL_F_CONSTRUCT_STATELESS_TICKET                 637
# define SSL_F_CREATE_SYNTHETIC_MESSAGE_HASH              539
# define SSL_F_CREATE_TICKET_PREQUEL                      638
# define SSL_F_CT_MOVE_SCTS                               345
# define SSL_F_CT_STRICT                                  349
# define SSL_F_CUSTOM_EXT_ADD                             554
# define SSL_F_CUSTOM_EXT_PARSE                           555
# define SSL_F_D2I_SSL_SESSION                            103
# define SSL_F_DANE_CTX_ENABLE                            347
# define SSL_F_DANE_MTYPE_SET                             393
# define SSL_F_DANE_TLSA_ADD                              394
# define SSL_F_DERIVE_SECRET_KEY_AND_IV                   514
# define SSL_F_DO_DTLS1_WRITE                             245
# define SSL_F_DO_SSL3_WRITE                              104
# define SSL_F_DTLS1_BUFFER_RECORD                        247
# define SSL_F_DTLS1_CHECK_TIMEOUT_NUM                    318
# define SSL_F_DTLS1_HEARTBEAT                            305
# define SSL_F_DTLS1_HM_FRAGMENT_NEW                      623
# define SSL_F_DTLS1_PREPROCESS_FRAGMENT                  288
# define SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS             424
# define SSL_F_DTLS1_PROCESS_RECORD                       257
# define SSL_F_DTLS1_READ_BYTES                           258
# define SSL_F_DTLS1_READ_FAILED                          339
# define SSL_F_DTLS1_RETRANSMIT_MESSAGE                   390
# define SSL_F_DTLS1_WRITE_APP_DATA_BYTES                 268
# define SSL_F_DTLS1_WRITE_BYTES                          545
# define SSL_F_DTLSV1_LISTEN                              350
# define SSL_F_DTLS_CONSTRUCT_CHANGE_CIPHER_SPEC          371
# define SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST        385
# define SSL_F_DTLS_GET_REASSEMBLED_MESSAGE               370
# define SSL_F_DTLS_PROCESS_HELLO_VERIFY                  386
# define SSL_F_DTLS_RECORD_LAYER_NEW                      635
# define SSL_F_DTLS_WAIT_FOR_DRY                          592
# define SSL_F_EARLY_DATA_COUNT_OK                        532
# define SSL_F_FINAL_EARLY_DATA                           556
# define SSL_F_FINAL_EC_PT_FORMATS                        485
# define SSL_F_FINAL_EMS                                  486
# define SSL_F_FINAL_KEY_SHARE                            503
# define SSL_F_FINAL_MAXFRAGMENTLEN                       557
# define SSL_F_FINAL_PSK                                  639
# define SSL_F_FINAL_RENEGOTIATE                          483
# define SSL_F_FINAL_SERVER_NAME                          558
# define SSL_F_FINAL_SIG_ALGS                             497
# define SSL_F_GET_CERT_VERIFY_TBS_DATA                   588
# define SSL_F_NSS_KEYLOG_INT                             500
# define SSL_F_OPENSSL_INIT_SSL                           342
# define SSL_F_OSSL_STATEM_CLIENT13_READ_TRANSITION       436
# define SSL_F_OSSL_STATEM_CLIENT13_WRITE_TRANSITION      598
# define SSL_F_OSSL_STATEM_CLIENT_CONSTRUCT_MESSAGE       430
# define SSL_F_OSSL_STATEM_CLIENT_POST_PROCESS_MESSAGE    593
# define SSL_F_OSSL_STATEM_CLIENT_PROCESS_MESSAGE         594
# define SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION         417
# define SSL_F_OSSL_STATEM_CLIENT_WRITE_TRANSITION        599
# define SSL_F_OSSL_STATEM_SERVER13_READ_TRANSITION       437
# define SSL_F_OSSL_STATEM_SERVER13_WRITE_TRANSITION      600
# define SSL_F_OSSL_STATEM_SERVER_CONSTRUCT_MESSAGE       431
# define SSL_F_OSSL_STATEM_SERVER_POST_PROCESS_MESSAGE    601
# define SSL_F_OSSL_STATEM_SERVER_POST_WORK               602
# define SSL_F_OSSL_STATEM_SERVER_PRE_WORK                640
# define SSL_F_OSSL_STATEM_SERVER_PROCESS_MESSAGE         603
# define SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION         418
# define SSL_F_OSSL_STATEM_SERVER_WRITE_TRANSITION        604
# define SSL_F_PARSE_CA_NAMES                             541
# define SSL_F_PITEM_NEW                                  624
# define SSL_F_PQUEUE_NEW                                 625
# define SSL_F_PROCESS_KEY_SHARE_EXT                      439
# define SSL_F_READ_STATE_MACHINE                         352
# define SSL_F_SET_CLIENT_CIPHERSUITE                     540
# define SSL_F_SRP_GENERATE_CLIENT_MASTER_SECRET          595
# define SSL_F_SRP_GENERATE_SERVER_MASTER_SECRET          589
# define SSL_F_SRP_VERIFY_SERVER_PARAM                    596
# define SSL_F_SSL3_CHANGE_CIPHER_STATE                   129
# define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM              130
# define SSL_F_SSL3_CTRL                                  213
# define SSL_F_SSL3_CTX_CTRL                              133
# define SSL_F_SSL3_DIGEST_CACHED_RECORDS                 293
# define SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC                 292
# define SSL_F_SSL3_ENC                                   608
# define SSL_F_SSL3_FINAL_FINISH_MAC                      285
# define SSL_F_SSL3_FINISH_MAC                 