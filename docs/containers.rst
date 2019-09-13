
Encrypted containers
------------------------

WIP OBSOLETE FORMAT

Witness Angel data is stored in a flexible container, which is a json/bson compatible data tree.

The idea is to allow each payload (media data, symmetric and asymmetric keys...) to be encrypted and signed by several entities one after the other.

A global UUID value is available to identify all containers related to a single Witness Angel device.
UUID overrides can exist at different levels of container data, to change the identifier used in transactions with third-party entities.

::

    Root dict:

        {
            data_ciphertext: <opaque multi-encrypted data bytestring>,
            data_encryption_strata: <list of Stratum Objects targeting ciphertext, in order of application>,
            data_uid: <optional uuid of this specific data container>,
        }

    Stratum Object:

        {
            signatures: <optional list of Signature objects for the parent ciphertext at this stratum of encryption>,

            encryption_algorithm: <encryption type label>,

            key_uid: <optional uuid of this specific encryption stratum>,

            # Then we have either:
            key_ciphertext: <opaque multi-encrypted key bytestring>,
            key_encryption_strata: <(optional) list of Stratum Objects targeting key_ciphertext, in order of application>,
            # or:
            key_escrow: <Escrow Entity object able to decrypt the parent data/key ciphertext at this stratum of encryption>,
        }

    Signature object:

        {
            signature_algorithm: <signature type label>,
            signature_payload: <opaque signature bytestring>,
            signature_escrow: <Escrow Entity object which signed the parent data/key ciphertext>,
            signature_uid: <optional uuid of this specific signature object>,
        }

    Escrow Entity:

        {
            escrow_type: <"standalone", "shared_secret" or other special values>,

            escrow_identity: <Public UUID or list of public UUIDs of escrow(s)>,

            escrow_operation_uid: <optional uuid of this specific escrow operation>,
        }



Example of container content::


    {
        data_ciphertext: "1989198ab1616...5262512916",  # Media data payload, here encrypted once using AES/OAEP and then ChaCha20-Poly1305
        data_encryption_strata: [
            {   # This is most probably the initial encryption by the WitnessAngel device, using third-party entities #

                signatures: [{
                    signature_algorithm: "SHA256_ECDSA">,
                    signature_payload: "129778af165cb222552",  # Signature of intermediate (transient) data ciphertext
                    signature_escrow: {escrow_type: "standalone", escrow_identity: "7a2c7658-4268-4193-9c03-23668a9d0b02"}
                }],

                encryption_algorithm: "AES_OAEP",

                key_ciphertext: "d12981628c1122de222",
                key_encryption_strata: [{
                    encryption_algorithm: "RSA",
                    key_escrow: {escrow_type: "standalone",
                                 escrow_identity: "e921cfe1-d32c-494c-b530-c29a1eee6ec4"}  # E.g. UUID of WitnessAngel owner
                },{
                    encryption_algorithm: "RSA",
                    key_escrow: {
                        escrow_type: "shared_secret",
                        escrow_identity: ["433a18ef-88aa-49bd-9e54-ae3ba8c11ccd",
                                          "8ece82b4-3df7-4375-a216-a7f9cbd28fd4",
                                          "47d187d5-27a9-4dfa-b60d-c79b250aa0f2"],
                        escrow_operation_uid: "2e17e379-acbe-48c2-80f3-bde4590b2696"
                    }
                }]
            },
            {   # This might be e.g. on over-encryption by the container storage manager #

                signatures: [],  # here, no signature of final (current) data ciphertext

                encryption_algorithm: "CHACHA20_POLY1305",

                key_ciphertext: "ba19278771298118226543ffd",
                key_encryption_strata: [{
                    encryption_algorithm: "RSA",
                    key_escrow: {escrow_type: "standalone",
                                 escrow_identity: "a014a4aa-f204-4868-85e2-ab983d3e239a"}
                }]
            },
        ]
    }
