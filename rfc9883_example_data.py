from typing import Optional, Union
from cryptography import x509
from cryptography.x509 import load_der_x509_csr, load_pem_x509_csr, load_der_x509_certificate, load_pem_x509_certificate
from pyasn1.codec.der import decoder, encoder

from pyasn1_alt_modules import rfc5280, rfc5652, rfc9480, rfc9883, rfc6402
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ
from pyasn1.type import namedtype

step2_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIIBhTCCAQsCAQAwPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQH
EwdIZXJuZG9uMQ4wDAYDVQQDEwVBbGljZTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BIAc+6lXN1MIM/82QeWNb55H0zr+lVgWVeF0bf4jzxCb5MCjVaM0eFEvcjXMV5p4
kzqiJTHC0V2JAoqYMX/DMFIcwZ7xP9uQd9ep6KZ+RXut211L8+W1QI1QJSDNxANR
saBQME4GCSqGSIb3DQEJDjFBMD8wDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCB4Aw
IgYDVR0RBBswGYEXYWxpY2VAZW1haWwuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwMD
aAAwZQIwPa2rOCe60edAF43C/t57IW8liyy+69FE04hMAFgw3Ga+nR+8zDuUsVLw
xXGAHtcDAjEA6LbvNkZjo6j2z5xRIjrHzEbGgiV4MF4xtnpfSSRI4dB0zT52bWkj
TZsuS1YWIkjt
-----END CERTIFICATE REQUEST-----"""

step3_alice_issued_cert = """-----BEGIN CERTIFICATE-----
MIICJzCCAa6gAwIBAgIUf3Sj/ANs4hR4XFlhTm+N8kxHqHkwCgYIKoZIzj0EAwMw
NzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0ExEzARBgNVBAMTCmNh
LmV4YW1wbGUwHhcNMjUwMTA5MTcwMzQ4WhcNMjYwMTA5MTcwMzQ4WjA8MQswCQYD
VQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xDjAMBgNVBAMT
BUFsaWNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgBz7qVc3Uwgz/zZB5Y1vnkfT
Ov6VWBZV4XRt/iPPEJvkwKNVozR4US9yNcxXmniTOqIlMcLRXYkCipgxf8MwUhzB
nvE/25B316nopn5Fe63bXUvz5bVAjVAlIM3EA1Gxo3YwdDAMBgNVHRMBAf8EAjAA
MAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUIx0A0f7tCzkQEZgYzH3NcM2L05IwHwYD
VR0jBBgwFoAUPpi8su/cNBu+cZLSo/ptvPJmQKowFwYDVR0gBBAwDjAMBgpghkgB
ZQMCATAwMAoGCCqGSM49BAMDA2cAMGQCMGu/Uypd7BaVnUjB36UtX9m5ZmPi78y5
1RA8WhbOv0KQVrcYtj4qOdiMVKBcoVceyAIwRJ6U91048NAb3nicHcrGFf1UYrhb
DlytK4tCa5HBxD/qAgy4/eUzA5NZwVaLK78u
-----END CERTIFICATE-----"""

step5_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIIEMTCCA7gCAQAwPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQH
EwdIZXJuZG9uMQ4wDAYDVQQDEwVBbGljZTB0MA4GBSuBBAEMBgUrgQQAIgNiAAQB
RyQTH+cq1s5F94uFqFe7l1LqGdEC8Tm+e5VYBCfKAC8MJySQMj1GixEEXL+1Wjtg
23XvnJouCDoxSpDCSMqf3kvp5+naM37uxa3ZYgD6DPY3me5EZvyZPvSRJTFl/Bag
ggL9MGcGCSqGSIb3DQEJDjFaMFgwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCAwgw
IgYDVR0RBBswGYEXYWxpY2VAZW1haWwuZXhhbXBsZS5jb20wFwYDVR0gBBAwDjAM
BgpghkgBZQMCATAwMIICkAYKKwYBBAGBrGACATGCAoAwggJ8ME8wNzELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0ExEzARBgNVBAMTCmNhLmV4YW1wbGUC
FH90o/wDbOIUeFxZYU5vjfJMR6h5MIICJzCCAa6gAwIBAgIUf3Sj/ANs4hR4XFlh
Tm+N8kxHqHkwCgYIKoZIzj0EAwMwNzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkV4
YW1wbGUgQ0ExEzARBgNVBAMTCmNhLmV4YW1wbGUwHhcNMjUwMTA5MTcwMzQ4WhcN
MjYwMTA5MTcwMzQ4WjA8MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNV
BAcTB0hlcm5kb24xDjAMBgNVBAMTBUFsaWNlMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEgBz7qVc3Uwgz/zZB5Y1vnkfTOv6VWBZV4XRt/iPPEJvkwKNVozR4US9yNcxX
mniTOqIlMcLRXYkCipgxf8MwUhzBnvE/25B316nopn5Fe63bXUvz5bVAjVAlIM3E
A1Gxo3YwdDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUIx0A
0f7tCzkQEZgYzH3NcM2L05IwHwYDVR0jBBgwFoAUPpi8su/cNBu+cZLSo/ptvPJm
QKowFwYDVR0gBBAwDjAMBgpghkgBZQMCATAwMAoGCCqGSM49BAMDA2cAMGQCMGu/
Uypd7BaVnUjB36UtX9m5ZmPi78y51RA8WhbOv0KQVrcYtj4qOdiMVKBcoVceyAIw
RJ6U91048NAb3nicHcrGFf1UYrhbDlytK4tCa5HBxD/qAgy4/eUzA5NZwVaLK78u
MAoGCCqGSM49BAMDA2cAMGQCL2TNHPULWcCS2DqZCCiQeSwx2JPLMI14Vi977bzy
rImq5p0H3Bel6fAS8BnQ00WNAjEAhHDAlcbRuHhqdW6mOgDd5kWEGGqgixIuvEEc
fVbnNCEyEE4n0mQ99PHURnXoHwqF
-----END CERTIFICATE REQUEST-----"""

step6_issued_cert = """-----BEGIN CERTIFICATE-----
MIICJTCCAaygAwIBAgIUf3Sj/ANs4hR4XFlhTm+N8kxHqHowCgYIKoZIzj0EAwMw
NzELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkV4YW1wbGUgQ0ExEzARBgNVBAMTCmNh
LmV4YW1wbGUwHhcNMjUwMTA5MTcwNTAwWhcNMjYwMTA5MTcwNTAwWjA8MQswCQYD
VQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xDjAMBgNVBAMT
BUFsaWNlMHQwDgYFK4EEAQwGBSuBBAAiA2IABAFHJBMf5yrWzkX3i4WoV7uXUuoZ
0QLxOb57lVgEJ8oALwwnJJAyPUaLEQRcv7VaO2Dbde+cmi4IOjFKkMJIyp/eS+nn
6dozfu7FrdliAPoM9jeZ7kRm/Jk+9JElMWX8FqN2MHQwDAYDVR0TAQH/BAIwADAL
BgNVHQ8EBAMCAwgwHQYDVR0OBBYEFAnLfJvnEUcvLXaPUDZMZlQ/zZ3WMB8GA1Ud
IwQYMBaAFD6YvLLv3DQbvnGS0qP6bbzyZkCqMBcGA1UdIAQQMA4wDAYKYIZIAWUD
AgEwMDAKBggqhkjOPQQDAwNnADBkAjARQ5LuV6yz8A5DZCll1S/gfxZ+QSJl/pKc
cTL6Sdr1IS18U/zY8VUJeB2H0nBamLwCMBRQ6sEWpNoeeR8Bonpoot/zYD2luQ1V
2jevmYsnBihKF0debgfhGvh8WIgBR69DZg==
-----END CERTIFICATE-----"""




id_statementOfPossession = univ.ObjectIdentifier('1.3.6.1.4.1.22112.2.1')

# privateKeyPossessionStatement Attribute

class PrivateKeyPossessionStatement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signer', rfc5652.IssuerAndSerialNumber()),
        namedtype.OptionalNamedType('cert', rfc5280.Certificate())
    )


def prepare_private_key_possession_statement(signer_cert: rfc5280.Certificate) -> rfc5280.Attribute:
    """Prepare a PrivateKeyPossessionStatement Attribute object."""
    priv_obj = PrivateKeyPossessionStatement()
    issuer_and_serial = rfc5652.IssuerAndSerialNumber()
    issuer_and_serial["issuer"] = signer_cert["tbsCertificate"]["issuer"]
    issuer_and_serial["serialNumber"] = signer_cert["tbsCertificate"]["serialNumber"]
    priv_obj["signer"] = issuer_and_serial
    priv_obj["cert"] = signer_cert

    attr = rfc5652.Attribute()
    attr["attrType"] = id_statementOfPossession
    attr_values = univ.SetOf(componentType=rfc5652.Attribute())
    attr_values.append(priv_obj)
    attr["attrValues"] = attr_values
    return attr


def _validate_possession_statement_subject(csr: rfc6402.CertificationRequest, priv_obj: rfc9883.PrivateKeyPossessionStatement):
    csr_subject = csr["certificationRequestInfo"]["subject"]
    priv_subject = priv_obj["cert"]["tbsCertificate"]["subject"]

    # According to RFC 9883, Section 2, The subject name matches the one from step 3. 
    # The CSR includes a signature that is produced with the private key from step 1

    if csr_subject != priv_subject:
        raise ValueError("Subject in CSR does not match that in possession statement cert")
    
def _validate_possession_statement_public_key(csr: rfc6402.CertificationRequest):
    # According to RFC 9883, Section 2, The subject composes a PKCS#10 CSR containing the key establishment public key. 
    csr_spki = csr["certificationRequestInfo"]["subjectPublicKeyInfo"]
    if not is_kem_establishment_key(csr_spki):
        raise ValueError("Public Key in CSR is not a key establishment key")


def is_kem_establishment_key(spki: rfc5280.SubjectPublicKeyInfo) -> bool:
    # This is a placeholder function. The actual implementation would check if the public key
    # is suitable for key establishment according to the relevant standards.
    # For demonstration purposes, we will assume it always returns True.
    raise NotImplementedError("is_kem_establishment_key function is not implemented")


def _get_private_key_possession_statement(csr: rfc6402.CertificationRequest) -> rfc9883.PrivateKeyPossessionStatement:
    """Retrieve the PrivateKeyPossessionStatement from the CSR.
    
    :param csr: The CertificationRequest object containing the possession statement.
    :return: The PrivateKeyPossessionStatement object.
    :raises ValueError: If the possession statement attribute is missing.
    """
    csr_obj, _ = decoder.decode(encoder.encode(csr), asn1Spec=rfc6402.CertificationRequest())
    attrs = csr_obj["certificationRequestInfo"]["attributes"]
     
    value = None
    for attr in attrs:
        if attr["attrType"] == rfc9883.id_statementOfPossession:
            if len(attr["attrValues"]) == 0:
                raise ValueError("Possession Statement Attribute has no values")
            if len(attr["attrValues"]) > 1:
                raise ValueError("Possession Statement Attribute has multiple values")
            value =  attr["attrValues"][0]

    if value is None:
        raise ValueError("Possession Statement Attribute not found in CSR")
    
    priv_obj, _ = decoder.decode(value, rfc9883.PrivateKeyPossessionStatement())

    return priv_obj

def _get_cert_from_possession_statement(csr: rfc6402.CertificationRequest) -> rfc5280.Certificate:
    """Retrieve the certificate from the PrivateKeyPossessionStatement in the CSR.
    
    :param csr: The CertificationRequest object containing the possession statement.
    :return: The certificate included in the possession statement.
    :raises ValueError: If the possession statement attribute is missing or does not contain a certificate.
    """
    priv_obj = _get_private_key_possession_statement(csr)

    if not priv_obj["cert"].isValue:
        raise ValueError("Possession Statement Attribute does not contain a certificate")

    return priv_obj["cert"]


def _get_sig_data_for_possession_statement(csr: rfc6402.CertificationRequest) -> bytes:
    """Retrieve the signature data for the possession statement from the CSR."""
    der_data = encoder.encode(csr)
    crypto_csr = load_der_x509_csr(der_data)
    return crypto_csr.tbs_certrequest_bytes
    # return encoder.encode(csr["certificationRequestInfo"])

_OID_TO_HASH = {
    '1.2.840.10045.4.3.2': hashes.SHA256,
    '1.2.840.10045.4.3.3': hashes.SHA384,
    '1.2.840.10045.4.3.4': hashes.SHA512,
}


def _select_signature_algorithm(csr: rfc6402.CertificationRequest):
    oid = str(csr["signatureAlgorithm"]["algorithm"])
    hash_cls = _OID_TO_HASH.get(oid)
    if hash_cls is None:
        raise ValueError(f"Unsupported signature algorithm OID: {oid}")
    return ec.ECDSA(hash_cls())


def validate_possession_statement_signature(
        csr: rfc6402.CertificationRequest,
        signature_cert: Optional[Union[rfc5280.Certificate, x509.Certificate]] = None) -> None:

    if signature_cert is None:
        signature_cert = _get_cert_from_possession_statement(csr)

    if isinstance(signature_cert, x509.Certificate):
        public_key_sig = signature_cert.public_key()
    else:
        der_data = encoder.encode(signature_cert["tbsCertificate"]["subjectPublicKeyInfo"])
        public_key_sig = load_der_public_key(der_data)

    sig_data = _get_sig_data_for_possession_statement(csr)
    signature = csr["signature"].asOctets()

    signature_algorithm = _select_signature_algorithm(csr)

    public_key_sig.verify(signature=signature, data=sig_data, signature_algorithm=signature_algorithm)

def validate_possession_statement(
        csr: rfc6402.CertificationRequest,
        signature_cert: Optional[Union[rfc5280.Certificate, x509.Certificate]] = None) -> None:
    priv_obj = _get_private_key_possession_statement(csr)
    signature_cert = signature_cert or _get_cert_from_possession_statement(csr)
    _validate_possession_statement_subject(csr, priv_obj)
    # _validate_possession_statement_public_key(csr)
    validate_possession_statement_signature(csr, signature_cert)



issued_cert = load_pem_x509_certificate(step3_alice_issued_cert.encode("ascii"))
csr5 = load_pem_x509_csr(step5_csr.encode("ascii"))

der_data = csr5.public_bytes(encoding=Encoding.DER)
obj, _ = decoder.decode(der_data, asn1Spec=rfc6402.CertificationRequest())


step2_csr_obj = load_pem_x509_csr(step2_csr.encode("ascii"))
print(step2_csr_obj.public_key())

der_data_cert = issued_cert.public_bytes(encoding=Encoding.DER)
cert_obj, _ = decoder.decode(der_data_cert, asn1Spec=rfc9480.CMPCertificate())

# validate_possession_statement(obj, issued_cert)


def test_validate_possession_statement():
    print("Testing possession statement validation...")
    csr5_der_data = csr5.public_bytes(encoding=Encoding.DER)
    csr5_obj, _ = decoder.decode(csr5_der_data, asn1Spec=rfc6402.CertificationRequest())
    spki = csr5_obj["certificationRequestInfo"]["subjectPublicKeyInfo"]
    spki["algorithm"]["algorithm"] = rfc5280.id_ecPublicKey