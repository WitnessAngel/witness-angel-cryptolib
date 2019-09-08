import copy
import json
import pprint
import uuid

import wacryptolib
from wacryptolib.encryption import encrypt_bytestring, decrypt_bytestring
from wacryptolib.key_generation import generate_symmetric_key, KEY_TYPES_REGISTRY, generate_asymmetric_keypair
from wacryptolib.signature import verify_signature
from wacryptolib.utilities import dump_to_json_bytes


LOCAL_ESCROW_PLACEHOLDER = "_local_"

def _get_proxy_for_escrow(escrow):
    import waserver.escrow_api
    if escrow == LOCAL_ESCROW_PLACEHOLDER:
        return waserver.escrow_api
    else:
        raise NotImplementedError("escrow system to be completed")




EXAMPLE_CONTAINER_CONF = dict(
    data_encryption_strata=[
        dict(data_encryption_type="AES_EAX",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[
                 dict(signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],),
        dict(data_encryption_type="CHACHA20_POLY1305",
             key_encryption_strata=[
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,),
                 dict(key_encryption_type=("RSA", "RSA_OAEP"),  # FIXME use subkey_type here
                      key_escrow=LOCAL_ESCROW_PLACEHOLDER,)
             ],
             signatures=[
                 dict(signature_type=("DSA", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER),
                 dict(signature_type=("ECC", "DSS"),  # FIXME use subkey_type here
                      signature_escrow=LOCAL_ESCROW_PLACEHOLDER)
             ],)
])




class CONTENT_TYPES:
    DATA = "data"  # Real media data
    KEY = "key"  # Cryptographic key
    CIPHERDICT = "cipherdict"  # Encrypted json dictionary (wrapping any of content types)



class ContainerWriter:

    def encrypt_data(self, data: bytes, conf):

        conf = copy.deepcopy(conf)  # So that we can manipulate it

        assert isinstance(data, bytes), data
        assert isinstance(conf, dict), conf

        container_uid = uuid.uuid4()

        # FIXME rename this
        data_ciphertext = data  # Initially unencrypted, might remain so if no strata
        result_data_encryption_strata = []

        for data_encryption_stratum in conf["data_encryption_strata"]:
            data_encryption_type = data_encryption_stratum["data_encryption_type"]
            symmetric_key = generate_symmetric_key(encryption_type=data_encryption_type)
            data_cipherdict = encrypt_bytestring(plaintext=data_ciphertext, encryption_type=data_encryption_type, key=symmetric_key)
            assert isinstance(data_cipherdict, dict), data_cipherdict
            data_ciphertext = dump_to_json_bytes(data_cipherdict)

            symmetric_key_data = symmetric_key  # Initially unencrypted, might remain so if no strata

            result_key_encryption_strata = []
            for key_encryption_stratum in data_encryption_stratum["key_encryption_strata"]:
                symmetric_key_cipherdict = self._encrypt_symmetric_key(container_uid=container_uid,
                                                                 symmetric_key_data=symmetric_key_data,
                                                                 conf=key_encryption_stratum)
                symmetric_key_data = dump_to_json_bytes(symmetric_key_cipherdict)  # Remain as bytes all along
                result_key_encryption_strata.append(key_encryption_stratum)  # Unmodified for now

            result_signatures = []
            for signature_conf in data_encryption_stratum["signatures"]:
                signature_value = self._generate_signature(container_uid=container_uid, data_ciphertext=data_ciphertext, conf=signature_conf)
                signature_conf["signature_value"] = signature_value
                result_signatures.append(signature_conf)

            result_data_encryption_strata.append(
                    dict(data_encryption_type=data_encryption_type,
                         key_ciphertext = symmetric_key_data,
                            key_encryption_strata=result_key_encryption_strata,
                        signatures=result_signatures)
            )

        return dict(
                uid=container_uid,
                data_ciphertext=data_ciphertext,
                data_encryption_strata=result_data_encryption_strata)


    def _encrypt_symmetric_key(self, container_uid: uuid.UUID, symmetric_key_data: bytes, conf: dict) -> bytes:
        assert isinstance(symmetric_key_data, bytes), symmetric_key_data
        subkey_type, key_encryption_type = conf["key_encryption_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        subkey_pem = encryption_proxy.get_public_key(uid=container_uid, key_type=subkey_type)
        subkey = KEY_TYPES_REGISTRY[subkey_type]["pem_import_function"](subkey_pem)

        key_cipherdict = encrypt_bytestring(plaintext=symmetric_key_data, encryption_type=key_encryption_type, key=subkey)
        return key_cipherdict

    def _generate_signature(self, container_uid: uuid.UUID, data_ciphertext: bytes, conf: dict) -> dict:
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        subkey_type, signature_type = conf["signature_type"]
        signature_value = encryption_proxy.get_message_signature(uid=container_uid, plaintext=data_ciphertext,
                                                            key_type=subkey_type, signature_type=signature_type)
        # FIXME remove "type" from inside signature!!!
        return signature_value


class ContainerReader:

    def decrypt_data(self, container: dict) -> bytes:
        assert isinstance(container, dict), container

        container_uid = container["uid"]

        data_ciphertext = container["data_ciphertext"]

        for data_encryption_stratum in reversed(container["data_encryption_strata"]):

            data_encryption_type = data_encryption_stratum["data_encryption_type"]

            self._verify_signatures(container_uid=container_uid, message=data_ciphertext, conf=data_encryption_stratum["signatures"])

            symmetric_key_data = data_encryption_stratum["key_ciphertext"]  # We start fully encrypted and unravel it
            for key_encryption_stratum in data_encryption_stratum["key_encryption_strata"]:
                symmetric_key_cipherdict = dump_to_json_bytes(symmetric_key_cipherdict)  # Remain as bytes all along
                symmetric_key_data = self._decrypt_symmetric_key(container_uid=container_uid,
                                                                 symmetric_key_cipherdict=symmetric_key_cipherdict,
                                                                    conf=key_encryption_stratum)




                #result_key_encryption_strata.append(key_encryption_stratum)  # Unmodified for now


            symmetric_key = self._decrypt_symmetric_key(key_ciphertext=data_encryption_stratum["key_ciphertext"],
                                         key_encryption_strata=data_encryption_stratum["key_encryption_strata"])

            data_ciphertext = decrypt_bytestring(plaintext=data_ciphertext, encryption_type=data_encryption_type, key=symmetric_key)


        return data_ciphertext

    def _decrypt_symmetric_key(self, container_uid: uuid.UUID, symmetric_key_cipherdict: bytes, conf: list):
        assert isinstance(symmetric_key_cipherdict, bytes), symmetric_key_cipherdict
        subkey_type, key_encryption_type = conf["key_encryption_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["key_escrow"])

        symmetric_key_plaintext = encryption_proxy.decrypt_with_private_key(uid=container_uid, key_type=subkey_type, cipherdict=symmetric_key_cipherdict)  # FIXME WRONG
        return symmetric_key_plaintext

        subkey = KEY_TYPES_REGISTRY[subkey_type]["pem_import_function"](subkey_pem)

    def _verify_signatures(self, container_uid: uuid.UUID, message: bytes, conf: dict):
        subkey_type, signature_type = conf["signature_type"]
        encryption_proxy = _get_proxy_for_escrow(conf["signature_escrow"])
        public_key = encryption_proxy.get_public_key(uid=container_uid, key_type=subkey_type)
        verify_signature(plaintext=message, signature=conf["signature_value"], key=public_key)  # Raises if troubles



if __name__ == "__main__":
    #writer = ContainerWriter()
    #result = writer.encrypt_data(b"qdjdnidazdazopdihazdoi", conf=EXAMPLE_CONTAINER_CONF)
    #pprint.pprint(result, width=120)


    container = {'data_ciphertext': b'{"ciphertext": {"$binary": {"base64": "MzNjMHRiYkJFd20yS0pEQjdZaU1nNHpKaE5yME9HVGo2NVREOVhxZzdVd'
                        b'nBlWFBZNnBrNVJRdVVQU1RmVytQUm1LV1lqQStEZE1lWnhQdFJ2L3VHRHNHWFpuVU9hemxRTmdZSzVoNmFEaWFSR3NoWnBEL'
                        b'y9Xb2hadkYxREV4OEYzRzdNRnJUbGlaMlhXWE1BUFhtekFPRVJlVTYrQ2t0cXBhN0xyTjFXVjJYb2JPUG5FamhPNUdPdFJlM'
                        b'3pxMzVlNjRMVnJqMVhyd1RUNUg5MHF5b0M5WFp1WHlmK0QvTEtWUVpzanMyRmUxME1zak02eTNQU1B6TE9aNnpIWHNFUisyK'
                        b'1A3RE04VTduQ0VTUnZEbnZ1MEIyNzNOWlZnUVI2dU1Ia2pnalh4dTQwaTNNNTMvcUtRSmdTUTVLeS9LZDkxRnoxZzdzVnhMT'
                        b'3NqZk1PeXV6NDNyVld3b0ZucTl4UHVJbHlFRkFuam1XY1lmWDdmblNsQ1Rjc2hQdCt3cnN0OXhxbk5DS081UT09", "subTy'
                        b'pe": "00"}}, "tag": {"$binary": {"base64": "d1Z6dUFhUStaa2pEZ2xqN0JNRFBUdz09", "subType": "00"}}'
                        b', "nonce": {"$binary": {"base64": "eHRmNGYyNmFjbkVFMU9reA==", "subType": "00"}}, "aad": {"$binar'
                        b'y": {"base64": "YUdWaFpHVnk=", "subType": "00"}}, "type": "CHACHA20_POLY1305"}',
                 'data_encryption_strata': [{'data_encryption_type': 'AES_EAX',
                                 'key_ciphertext': b'{"digest_list": [{"$binary": {"base64": "bEs4bVlwa1o3Z0t1K25XU28wWFB'
                                                   b'ZMnI4b2hIbUZnTDFCeXd2U0RJVEJtVXAwenIwdmZkNXhMeG03Ukh6OHI1V0RnaGc2bVB'
                                                   b'YSk5PVGx5amhsbjNrbHlmMkpUdmxZbmp0RWxxQkVJU0F3SW1PRjVJOHlPVmtBcmM2dFZ'
                                                   b'PV1VTUVk2aXRncG9NVnRLbUR6MGwwSXRPTTRtZnYvZ21QaGRNU2cxRm5kM3lqanBWNzB'
                                                   b'QN0szWUpxZk1ta2lEa2NYSEFqbGR3RnZTcTNqN3p0bjhWa3JNb0FvdE5rRTJNbXRDdDJ'
                                                   b'UamJSWS80cEMrbnljbEdKQWhHT0R4TnhVVTBQM0NwMUFjWGdkanUvbTZHcE9ZRklVRVN'
                                                   b'6NmJpVnlOWTJxa0cvRFFMNTI2YzVJYUtCeUwra3B6Z08wMkpQZUFTVUkyOVcwNGdIVVN'
                                                   b'0ZGF2eEY3cmxuVGh4anFRPT0=", "subType": "00"}}], "type": "RSA_OAEP"}',
                                 'key_encryption_strata': [{'key_encryption_type': ('RSA', 'RSA_OAEP'),
                                                            'key_escrow': '_local_'}],
                                 'signatures': [{'signature_escrow': '_local_',
                                                 'signature_type': ('DSA', 'DSS'),
                                                 'signature_value': {'digest': b'\x14\x90\x82Rw\x0ey\x80/\x8cIn'
                                                                               b'\xdf\xf4?\xaa+\xf0\xa9R\xbaA\x0e\x1f'
                                                                               b'\xc1-9\x00\xcddr\xb6\x07\xca\x01p'
                                                                               b'W\x84\x05\xcc\x9b\x85\x85\x89)-l\xd9'
                                                                               b'\xf1H\r@\x03\x1d\xe1Z',
                                                                     'timestamp_utc': 1567927317,
                                                                     'type': 'DSS'}}]},
                                {'data_encryption_type': 'CHACHA20_POLY1305',
                                 'key_ciphertext': b'{"digest_list": [{"$binary": {"base64": "WFFJcnJuazlJTGoyaFJyRTd6ekh'
                                                   b'PLzZvVEpENURXalZabnFXVldEb01rdlFMTlYvS2cvZTMyZW95RG4yd2xFWFlqRFppQUF'
                                                   b'MQXBuS05mMWp0TmxXMEZOSmw4V1lmVDJBaXUzZVJnMVNjZGgrSUtOWTBLdmh5Y21sNnd'
                                                   b'CVytyTDhsMTZZN1RDN0JwSyttdXVhSC91cEZncE9ScWEwazJnVGY4WjU5TFVpb1ZNRmt'
                                                   b'kK2NKMlRlL2pyaGtLL3ZwYk9jWFAzNXY3Sk5Ub2I0bnBBa0pmKzZ1WllpTFF0SVlHZVN'
                                                   b'rN0VHNmtmVUhuMDZvMkdxRGRNa2hTVHJvUXFoWm44YWN5bTZUWElLd1VjNjFPMHBDZlE'
                                                   b'ybENKdjNZZE5sK3V2TDNUSkhrV3NWaVcrU1BXNmhRTXQzSWlTblNtV0JEZGlJTURMTmY'
                                                   b'rZ05WRjc3eVQ2TUw1Y3N3PT0=", "subType": "00"}}, {"$binary": {"base64"'
                                                   b': "Y3Q0eGlWYkZuMGU4MDMwcDQ3bG5Za1psNmxlTGpFZjYvRmhWZWNrckdEVTYwbmJBO'
                                                   b'ERUYUtBYTFtTDZZNXpSSy8wTVVhaHI3TkxWd0YveUpoNHN4SHdkWEtUc2VGZVNIR1RUS'
                                                   b'Wk1dUNGcGxlalgyM3hPWHBCQkh4S09lV29jblpFNUY3U2tDajNVYVBTVzNGZnFhOHNVT'
                                                   b'3RYVE0wVFlVemlvby81UEwzYUR4Q1Q0aGkwVkx5V3p5UG5nbWg0TDA4Qzd4OTRMYU9rb'
                                                   b'DZsVGhQS3JwSkIrS1VqSFROdUJlSGt5SEFvYTUyTU9FTjRDdHZ6V3lDeTV4MGwxYnd4V'
                                                   b'3pJMXJrZjZLNGN2UnNZai96NkRuNzAwWVhQMzYydzhEQm04bzNlWjlFeHZHbDgvVXI4M'
                                                   b'kFDNDZpWWxTVTlYOGdDRERpSTNsWGxHVHh2SzEyWHE1ek5ta0tRPT0=", "subType":'
                                                   b' "00"}}, {"$binary": {"base64": "bmhBamhtRjlKSFJFSC9iWERGeGEyN2tYSEk'
                                                   b'yMGgxL1pHeGpoOFZZMzl1WnE5RklKaDRtTWxaRnRxRUZ6OXM1dmYyK1g2SjNXb2g5dk5'
                                                   b'UVWVjRFdiTEk5SFNDa1JpUGFQNiswU1JDd3ZoNDZYQkF2YzhnQjQrWUpybTY3WHJqbGF'
                                                   b'6MWRBOFFkR3BleWMydmsyenRnblY5T3hHU1A4dTVzc3NUZnRXY1RzM0F5c3NFQUt1YTl'
                                                   b'iVVVsMFhDUXR1blZLclVjRG1xV3lGVHh5ZWp4dk1SZ3JzbXZrNFhkY1l0K0FOcHo2MnF'
                                                   b'SLzJFTlZnazZDTWoxbHpHeEhiS1FyQzJ5QWVQcDQ0ZUZpS1Jya3RTakJyQ1RISmVSU09'
                                                   b'PdDRpaCt5ektkckNEblpsTGs3K1JzMnByNFJoRjh4aDlPY2R2bVRXTzhZTFY5clZVUll'
                                                   b'BRHY2bUNyb0pBPT0=", "subType": "00"}}, {"$binary": {"base64": "TnFkW'
                                                   b'HVZaVdhNCtHcHFlWUptNmZkQmVSYjlZclE1VkJBbndWUGQ3WEd3MUtLK1A3UXBrMFREW'
                                                   b'HBXQnBxSW5kVnJQb3JaekszK2JEd1R1bUJXcDdJYjlkWEZxcFRvT2lrMVJndENjR0h3b'
                                                   b'zdnajE5SjdJUmJSNXk5YzFDTDdkeFI2bHZuTm41NjNxRXh6UzdKTUs5dk51dWI1a1Fnc'
                                                   b'WV3Y01wc05tV25Lb3JBaCsxOGhHS0VSL05IWG5TUlR6Qm5QN0dMTjNGWCtBd2FlTUlsa'
                                                   b'E91TGFsTXh2VGtXbEd4LzVReHBMTEZDMzI4VVdKQndaT3poei90dXRlN0NnOUl4SnVhS'
                                                   b'ThNWXpUQW5WS3p2YWxCSDVSamhuVVc1MEI5MlpxSlh4TGozQXphTVJlZHMydlRvQjEyb'
                                                   b'FhydHhhVWdYakRnajZaS2FPTEI1UnZJY0ZHRkFCVkh3PT0=", "subType": "00"}},'
                                                   b' {"$binary": {"base64": "WEU4Z1Fjb2dMS1V5RENLZTdjTW5SWUQ0Y1RPdkxzL0k'
                                                   b'yRTJzTUR4SHBDTHVoQWVObDc4aVc4Y25YZ3cza3ZHeG1zYUd5OWRqVkdUMEFramthOEF'
                                                   b'4Mnc4cmRBMXJBZ1ZpS0N6QlJKZWZ2dVhtK2RGQzNGWjVDVGhhZGNLNUtYS0dDM0NqSHl'
                                                   b'EcXJTaVZ4U0gvOGxyaWg0VDIxWXkvNTByUVZXVEZSZCtMd0xDS2tmczFIR1g4SmxBNVl'
                                                   b'leW04RnRvc0NKQmo0S0tJR2dxZy9oZnJ2cGxpdVU2bkZUcFVicllJSGZjbkUyUVJDS3F'
                                                   b'DNkc4UnM1Tnh4eEs4N2lmbzhrUWpJWlF1TEY5QXhrQW8xY2xNVVVQTFlYeTNOQlFOUzR'
                                                   b'TTFVPRzRTVWFoQ0JKRVA1MDFOTmpJdEk0NEhpUm9xMitML0lTaWdpbnpuaFk4M2JpLzR'
                                                   b'YaDh3PT0=", "subType": "00"}}, {"$binary": {"base64": "bjFiRkl3cGV2d'
                                                   b'jhlSnE4R0xmT0dmSjBMUnJwY2hoejQ0OEZsc0JUQnF0dnl1N3ZDK24zUVBuKzZvUUxkW'
                                                   b'HBmMDgyUWJqSkVIYVZnM09vNUVZeERQaGV3SjFGaVN6S1B5Q2xmL1NrdEFKOUFBakRLb'
                                                   b'HViY2NtRkRzaDhXbnBBV2VMSEJpR2RVNExSN3JRSlI2dS9FaWxoeGdld0Z1VjBRLzIwa'
                                                   b'zFQRmJmdHlQN2NWSHRVby9PblJSejhBWDZtTXdFdEJvdHR0Y09vRmVXWk54U3VleXl1e'
                                                   b'WtaTWtTYkZJbGVTbEdCSDJpTU1sMkdYek5LR1pTMUN4RU80emdkUzMwM2xVS1c5ZjlwV'
                                                   b'GY1VUZVb1M3TStEY2xVclJrckZ3dzAzOXJGNCtPek9DYlBMZkMwaFk5cFZKT2V0TzNyS'
                                                   b'HJrdjZraG1zdk9BMGxQR3JvY2dxYkVmZDhnPT0=", "subType": "00"}}, {"$bina'
                                                   b'ry": {"base64": "bGRJZHdMSC9DRVl6WVlTaGxaZGhiM2pZU0ZxTGg0YlZpaHAzb1J'
                                                   b'1d0lvU1c1OUx0NE9rRExUSmw2d1NtVDBBVXkwMm9IQXNmaDA0dkJDbS90bG9wdDdMNDh'
                                                   b'vNEpuSk5nOTdCU052TjhTdUMySG9SSDRuMzc0Q2xKbTVLTXRmSkM2aktHbU1jYnhtY1l'
                                                   b'yeExET2tHQW9PMEYycmxLQ3BRMUFpVWFGYzI4L2NnRXQvNnRINkFSalVBMDREZGt2R0V'
                                                   b'GbzYzYWtPSEhvaXdxRkJTVzJ4WnZTcDNuOTEyaGFMRGhadVhxTXBxQjdjZDlFQ3pNWlZ'
                                                   b'nQllYdDZBRXRlU0xheEZaazF5Nm96NlN1MDQrdnpXK2lWbjM4Zmdnelp0NDFjUGZEMml'
                                                   b'va0g5NjNtZUlvY0haSWlGSTZFL2FTK00zYytGYkdlZmpOdndBOEpQYmp4R0I3a2xnPT0'
                                                   b'=", "subType": "00"}}, {"$binary": {"base64": "bVNFTU1GeVlUbmU3U3pkS'
                                                   b'G5YcGVhUTJMcmRlWUxLbDduNm82cW14ZkpmWlpSUHU1Ykh5Njl1OTZSeHdBQm9Ic0Fse'
                                                   b'kdJeFZQMHZId2tTZU56aTR1QTRZUkFHSDVZYnkzeGhYWWFCNVIxNkhMeEw2dXlzUGNnM'
                                                   b'W9TNWcrV3c0SGNmU0VPVlBVRXFGc3JrbEttMXA3bFVnWXAyRTB1KzZFQWNCOE9UNXZRU'
                                                   b'k5iWmlNZm9CZm45YSs3ZVo5N1EwQmJWOUZJM0puQUVnck42YTRIam82TWFZM2dNVGtBb'
                                                   b'3FjeWpyT2paSDJkOHdYQmtTaGw5VHVFd2twWWo4eEp4YzB5aDFPekk1d29qdGk0MDZOe'
                                                   b'mk5RFNWZWI5UFJ4OVU0cGpXM3pEYkk2T2dKWUU1UkFldkRRZlhiR3BWMm5rRmxOMC8vY'
                                                   b'lRRV2xYcFhuRVRabTdhNTVDdlhBPT0=", "subType": "00"}}, {"$binary": {"b'
                                                   b'ase64": "ZG40ZktQcEtFem5xRjV3SHBSUml6djBRY3RMbmp1dUoxSXZvL0Y0eURibk1'
                                                   b'UTElJbmtWNUVjWGs5QkFvU0JXa0tVbVNiMnVpYk11dHJFOE42azgrbm82RlJ4WmtMQzN'
                                                   b'JSkdDbEpVZnBjSDViSWFwSFJ6T040MmtOT2Ewd2JmbkFXRHdaT0FIeW0wNFF6VnRDaW4'
                                                   b'1K0xBZ3pCWitZSnc3OUNoVmVJYUFoNGJXOEtCejB2MU9VTFlvVUFnZHEvdnZYWFFvSGt'
                                                   b'BY0ZvYnFQVHg0WFlxaXBFOFB5YmZnVTFXRENqVlBpZkhlQ1V0M05CQnh1c2NZM2VXVTR'
                                                   b'ueXBkTmRRVXVZelBpUW1zbXVFTWd2TENRelpqaXVvcHR0d0htK3gwRjRGdXdiKzQxM3Z'
                                                   b'xS2FicER6a0x3ZmtCNGJLS2tIRGF1eGpXakN6c3J5dDVwVUtXTS9mZmtRPT0=", "sub'
                                                   b'Type": "00"}}, {"$binary": {"base64": "RTFsSHZJSTYwVE5zSlBKanUwQ3c1S'
                                                   b'E1tSzV5RTVUbGNETW8vYkdmQUMwTHljYURmdmdHeXFZQ0wxVkVKRHhyNThSekhnRjI0T'
                                                   b'0tybGp6cjArazJjM1pOZjhORE5kdHQwS3hpUitVYzY0ZCtaT2xzaXJUV0dVSTJuNFd2d'
                                                   b'DI0UzlhclB0RDFrdDBTR2tBS01oc1hMcTIwZ1BlVEdlcHkwd0lqZGpHbHRoRmQrWG1mQ'
                                                   b'k5DNStDOXlFQUgrT2cwMHNDTUFmbGx0T0lVZlczRElMaldkUmZDRXZqRUJSOU1tL3NLR'
                                                   b'nZEZFRBdGlkWG4yY0tOQWV2N1VFUnNIYlhQSFNRRnlWdlRzUHNJeTRDNnlTdnFVNGJQa'
                                                   b'TVQUWptSWUwSzJJMEg1VTVjdzFzUUtpZ0FzL0pmU2plMjlSZDk1cFFRWnBUMmhza1pBM'
                                                   b'EZxZzgrN2RENGUwa053PT0=", "subType": "00"}}], "type": "RSA_OAEP"}',
                                 'key_encryption_strata': [{'key_encryption_type': ('RSA', 'RSA_OAEP'),
                                                            'key_escrow': '_local_'},
                                                           {'key_encryption_type': ('RSA', 'RSA_OAEP'),
                                                            'key_escrow': '_local_'}],
                                 'signatures': [{'signature_escrow': '_local_',
                                                 'signature_type': ('DSA', 'DSS'),
                                                 'signature_value': {'digest': b'S\xacd\x92\xc4E\x88%\x15h\xfd\xc9'
                                                                               b'\xf6\x86\x9f\x8e\xa0gx\xb0\xc3w\xd9\xf2'
                                                                               b'z[\xf3\xb2EC\x19-rkQVD#<\xe8s\xd5b\xde'
                                                                               b'\x16\x96\xdbz\x19tD\xf3\xc7\xbf\xd1G',
                                                                     'timestamp_utc': 1567927319,
                                                                     'type': 'DSS'}},
                                                {'signature_escrow': '_local_',
                                                 'signature_type': ('ECC', 'DSS'),
                                                 'signature_value': {'digest': b'\x00\x89\xcd\x06\xfd\x98\xa1\x9f'
                                                                               b'9\xed\xf3\x0e\x04\xe4\xf3\xe2\x01_G\xb9'
                                                                               b'D\n\x82\x97\xc6@-\xfdH\xd8\xbe\xaf'
                                                                               b"'\x81\x12\x18({\xbf\xd5E\x9d0\x08"
                                                                               b'\x98y\x0fUg\xc5\x98\x17V}\xb1\xcf'
                                                                               b'\xd6\x91\xe0\xd5n\r\x9b\x13\x9eR\x01\xfd'
                                                                               b'y\xc8\xa8\xc2\xed\xd5"\xc1\xd1"\xbb\xbd'
                                                                               b'\xdc\\\x9cE\xd0,H\xc8\xd3:\x02\xf3'
                                                                               b'\xa9\xda\xa8\xe7!uD"+\xc2ku\x06\xd9h\x94'
                                                                               b'\x1c\x06\x98\x83UG\xcc\xcc-\xae\xebk'
                                                                               b'\x8a\x96\xc5\xd6\xe9\xc0\xec\x9d'
                                                                               b'3\x1e\x9b\x90',
                                                                     'timestamp_utc': 1567927319,
                                                                     'type': 'DSS'}}]}],
     'uid': uuid.UUID('a8b977f7-dc55-45d0-831b-6f4251b4384f')}

    reader = ContainerReader()
    result = reader.decrypt_data(container)
    pprint.pprint(result, width=120)
