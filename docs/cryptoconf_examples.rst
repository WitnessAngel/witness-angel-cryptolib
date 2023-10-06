
Cryptoconf examples
===================================

Simple cryptoconf
+++++++++++++++++++++++++++

Below is a minimal cryptainer configuration in python format, with a single encryption layer and its single signature, both backed by the local "trustee" (or "key guardian") of the device; this workflow should not be used in real life of course, since the data is not protected against illegal reads.

::

    {
      "payload_cipher_layers":[
        {
          "key_cipher_layers":[
            {
              "key_cipher_algo":"RSA_OAEP",
              "key_cipher_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ],
          "payload_cipher_algo":"AES_CBC",
          "payload_signatures":[
            {
              "payload_digest_algo":"SHA256",
              "payload_signature_algo":"DSA_DSS",
              "payload_signature_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ]
        }
      ]
    }

A corresponding cryptainer content, in Pymongo's Extended Json format (base64 bytestrings shortened for clarity), looks like this.
Binary subType 03 means "UUID", whereas subType 00 means "bytes".

::

    {
      "cryptainer_format":"cryptainer_1.0",
      "cryptainer_metadata":null,
      "cryptainer_state":"FINISHED",
      "cryptainer_uid":{
        "$binary":{
          "base64":"Du14m64eb4m/+/uCPAkEqw==",
          "subType":"03"
        }
      },
      "keychain_uid":{
        "$binary":{
          "base64":"Du14m64emE23Dnuw4+aKFA==",
          "subType":"03"
        }
      },
      "payload_cipher_layers":[
        {
          "key_cipher_layers":[
            {
              "key_cipher_algo":"RSA_OAEP",
              "key_cipher_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ],
          "key_ciphertext":{
            "$binary":{
              "base64":"eyJkaWdlc3Rfb...JzdWJUeXBlIjogIjAwIn19XX0=",
              "subType":"00"
            }
          },
          "payload_cipher_algo":"AES_CBC",
          "payload_macs":{
          },
          "payload_signatures":[
            {
              "payload_digest_value":{
                "$binary":{
                  "base64":"XgNeHINsXw16Tl...WtknjGh93nMB4v09Y=",
                  "subType":"00"
                }
              },
              "payload_digest_algo":"SHA256",
              "payload_signature_algo":"DSA_DSS",
              "payload_signature_struct":{
                "signature_timestamp_utc":{
                  "$numberInt":"1641305798"
                },
                "signature_value":{
                  "$binary":{
                    "base64":"F/q+FZQThx1JnyUCwwh...59NCRreWpf2BK8673qMc=",
                    "subType":"00"
                  }
                }
              },
              "payload_signature_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ]
        }
      ],
      "payload_ciphertext_struct":{
        "ciphertext_location":"inline",
        "ciphertext_value":{
          "$binary":{
            "base64":"+6CAsNlLHTHFxVcw6M9p/SK...axRM3poryDA/BP9tBeaFU4Y=",
            "subType":"00"
          }
        }
      }
    }


Complex cryptoconf
+++++++++++++++++++++++++++

Below is a python data tree showing all the types of node possible in a cryptoconf.

We see the 3 currently supported types of trustee: `local_keyfactory`, `authenticator` (with a keystore_uid), and `jsonrpc_api` (with a jsonrpc_url).

We also see how share secrets, symmetric ciphers, and asymmetric ciphers (RSA_OAEP and its attached trustee) can be combined to create a deeply nested structure.

::

    {
      "payload_cipher_layers":[
        {
          "key_cipher_layers":[
            {
              "key_cipher_algo":"RSA_OAEP",
              "key_cipher_trustee":{
                "jsonrpc_url":"http://www.mydomain.com/json",
                "trustee_type":"jsonrpc_api"
              }
            }
          ],
          "payload_cipher_algo":"AES_EAX",
          "payload_signatures":[
          ]
        },
        {
          "key_cipher_layers":[
            {
              "key_cipher_algo":"RSA_OAEP",
              "key_cipher_trustee":{
                "keystore_uid":UUID("320b35bb-e735-4f6a-a4b2-ada124e30190"),
                "trustee_type":"authenticator"
              }
            }
          ],
          "payload_cipher_algo":"AES_CBC",
          "payload_signatures":[
            {
              "payload_digest_algo":"SHA3_512",
              "payload_signature_algo":"DSA_DSS",
              "payload_signature_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ]
        },
        {
          "key_cipher_layers":[
            {
              "key_cipher_algo":"[SHARED_SECRET]",
              "key_shared_secret_shards":[
                {
                  "key_cipher_layers":[
                    {
                      "key_cipher_algo":"RSA_OAEP",
                      "key_cipher_trustee":{
                        "trustee_type":"local_keyfactory"
                      }
                    },
                    {
                      "key_cipher_algo":"RSA_OAEP",
                      "key_cipher_trustee":{
                        "trustee_type":"local_keyfactory"
                      }
                    }
                  ]
                },
                {
                  "key_cipher_layers":[
                    {
                      "key_cipher_algo":"AES_CBC",
                      "key_cipher_layers":[
                        {
                          "key_cipher_algo":"[SHARED_SECRET]",
                          "key_shared_secret_shards":[
                            {
                              "key_cipher_layers":[
                                {
                                  "key_cipher_algo":"RSA_OAEP",
                                  "key_cipher_trustee":{
                                    "trustee_type":"local_keyfactory"
                                  },
                                  "keychain_uid":UUID("65dbbe4f-0bd5-4083-a274-3c76efeecccc")
                                }
                              ]
                            }
                          ],
                          "key_shared_secret_threshold":1
                        },
                        {
                          "key_cipher_algo":"RSA_OAEP",
                          "key_cipher_trustee":{
                            "trustee_type":"local_keyfactory"
                          }
                        }
                      ]
                    }
                  ]
                },
                {
                  "key_cipher_layers":[
                    {
                      "key_cipher_algo":"RSA_OAEP",
                      "key_cipher_trustee":{
                        "trustee_type":"local_keyfactory"
                      }
                    }
                  ]
                },
                {
                  "key_cipher_layers":[
                    {
                      "key_cipher_algo":"RSA_OAEP",
                      "key_cipher_trustee":{
                        "trustee_type":"local_keyfactory"
                      },
                      "keychain_uid":UUID("65dbbe4f-0bd5-4083-a274-3c76efeebbbb")
                    }
                  ]
                }
              ],
              "key_shared_secret_threshold":2
            }
          ],
          "payload_cipher_algo":"CHACHA20_POLY1305",
          "payload_signatures":[
            {
              "keychain_uid":UUID("0e8e861e-f0f7-e54b-18ea-34798d5daaaa"),
              "payload_digest_algo":"SHA3_256",
              "payload_signature_algo":"RSA_PSS",
              "payload_signature_trustee":{
                "trustee_type":"local_keyfactory"
              }
            },
            {
              "payload_digest_algo":"SHA512",
              "payload_signature_algo":"ECC_DSS",
              "payload_signature_trustee":{
                "trustee_type":"local_keyfactory"
              }
            }
          ]
        }
      ]
    }


Here is a summary of the same cryptoconf, as returned for example by the CLI "summarize" command.

::

    Data encryption layer 1: AES_EAX
      Key encryption layers:
        RSA_OAEP via trustee 'server www.mydomain.com'
      Signatures: None
    Data encryption layer 2: AES_CBC
      Key encryption layers:
        RSA_OAEP via trustee 'authenticator 320b35bb-e735-4f6a-a4b2-ada124e30190'
      Signatures:
        SHA3_512/DSA_DSS via trustee 'local device'
    Data encryption layer 3: CHACHA20_POLY1305
      Key encryption layers:
        Shared secret with threshold 2:
          Shard 1 encryption layers:
            RSA_OAEP via trustee 'local device'
            RSA_OAEP via trustee 'local device'
          Shard 2 encryption layers:
            AES_CBC with subkey encryption layers:
              Shared secret with threshold 1:
                Shard 1:
                  RSA_OAEP via trustee 'local device'
              RSA_OAEP via trustee 'local device'
          Shard 3 encryption layers:
            RSA_OAEP via trustee 'local device'
          Shard 4 encryption layers:
            RSA_OAEP via trustee 'local device'
      Signatures:
        SHA3_256/RSA_PSS via trustee 'local device'
        SHA512/ECC_DSS via trustee 'local device'
