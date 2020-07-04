'''
An ECC-based access control scheme with lightweight decryption and conditional authentication for data sharing in vehicular networks

| Published in: Soft computing
| Available From: https://link.springer.com/article/10.1007/s00500-020-05117-x


| Notes: authentication part

:Authors:    Qin
'''

from ecqv.relic import librelic
from ecqv.ec import *
from ecqv.bi import *
from ecqv.common import *



G = generatorEc()
N = orderEc()
def _exp(cert, idText):
    """
    Generates the exponent e by hashing @cert and @idText.
    """
    return hashZ(str(serializeEc(cert)) + idText)


def ecqv_anony_sign(idText, request, caPrivkey, authoritykey):
    """
    A certificate authority (CA) generates an implicit certificate using 
    identity string @id, @request (certificate public key component), and 
    the CA's private key @caPrivkey.
    @returns (s, cert) where @r is the private key contribution and @cert is 
     the implicit certificate.
    """
    # Verify input types
    assertType(request, ec1Element)
    assertScalarType(caPrivkey)

    # Switch to new notation
    R = request
    d = caPrivkey

    # TODO: use simultaneous mul to speed this up.
    # Random integer
    k = randomZ(N)
    P = R + k*G
    s = randomZ(N)
    t = authoritykey

    # TODO: 𝐶𝐼𝐷=(𝐼𝐷+ s∙𝑡∙𝐺,s∙𝐺)
    # str2byte = idText.encode('utf-8')
    # byte2str16 = str2byte.hex()
    # CID_2 = s * G
    # id_point = deserializeEc(bytearray(bytes.fromhex(byte2str16)))
    # CID_1 = id_point + (t * CID_2)
    # CID = (serializeEc(CID_1)).hex() + ' '+ (serializeEc(CID_2)).hex()
    # cert = (serializeEc(P)).hex() + ' ' + CID  #avoid error:UnicodeDecodeError: 'utf-8' codec can't decode byte 
    # # Hash the identity string and implicit cert into an integer
    # e = hashZ(cert)

    # cert1 = cert.split(' ')
    # c1 = deserializeEc(bytearray(bytes.fromhex(cert1[1])))  #CID_1
    # c2 = deserializeEc(bytearray(bytes.fromhex(cert1[2])))  #CID_2
    # id_point1=c1-t *c2
    # point2array = serializeEc(id_point1)
    # 
    # print(point2array)
    # if point2array==bytearray(str2byte): print("equal")

    # easy way
    str2byte = idText.encode('utf-8')
    byte2str16 = str2byte.hex()

    num2int = int(byte2str16,16)
    idnum = num2int
    CID_2 = s * G
    CID_2_x=int(CID_2.getPoint()[0].encode('utf-8').hex(),16)
    CID_1_x = idnum + (t * CID_2_x)

    CID = str(CID_1_x) + ' '+ str(CID_2_x)
    cert = (serializeEc(P)).hex() + ' ' + CID  #avoid error:UnicodeDecodeError: 'utf-8' codec can't decode byte 
    # Hash the identity string and implicit cert into an integer
    e = hashZ(cert)


    # Compute the private key contribution
    r = (e*k + d) % N


    return (r, cert)


def ecqv_anony_validate(idText, alpha, r, cert, caPubkey):
    """
    A server can validate an implicit certificate response using identity
    string @idText, private value @alpha (used to generate cert request),
    and the certificate response @r (private key component) and implicit
    @cert.
    @raises Exception if the certificate response is invalid.
    @returns (privkey, pubkey)
    """
    # Verify parameter types
    assertScalarType(alpha)
    assertScalarType(r)
   # assertType(cert, ec1Element)
    assertType(caPubkey, ec1Element)

    G = generatorEc()

    # Compute the private key @s
    strs = cert.split(' ')
    P = deserializeEc(bytearray(bytes.fromhex(strs[0])))  
    e = hashZ(cert)
    s = (e*alpha + r) % orderEc()
    # Compute the public key two ways: using the privkey and using the cert
    # (the way a client will compute it)
    # The easy way
    S1 = s*G

    # Using the cert
    S2 = e*P + caPubkey

    # The two techniques should produce the same pubkey value -- raise an
    # exception if they don't match
    if S1 != S2:
        raise Exception("Implicit certification response failed validation")
    return s, S1


def ecqv_anony_recoverPubkey(idText, cert, caPubkey):
    """
    A client can recover the server's pubkey using the identity string @idText,
    server's implicit @cert, and the trusted @caPubkey.
    """
    # Verify types
   # assertType(cert, ec1Element)
    assertType(caPubkey, ec1Element)
    strs = cert.split(' ')
    P = deserializeEc(bytearray(bytes.fromhex(strs[0])))
    # Compute the pubkey
    return hashZ(cert)*P + caPubkey

def ecqv_anony_recoverRealid(cert, authoritykey1):
    strs = cert.split(' ')
    t = authoritykey1
    # TODO: 𝐼𝐷=(𝐼𝐷+ s∙𝑡∙𝐺-𝑡∙s∙𝐺)
    # c1 = deserializeEc(bytearray(bytes.fromhex(strs[1])))  
    # c2 = deserializeEc(bytearray(bytes.fromhex(strs[2])))
    # idText = serializeEc(c1 -t*c2).hex()

    # easy way
    cert = cert.split(' ')
    c1 = int(cert[1])  #CID_1
    c2 = int(cert[2])  #CID_2
    idnum=c1-t *c2

    idText = bytes.fromhex(format(idnum,'x')).decode('utf-8')

    return idText


if __name__ == "__main__":

    caPrivkey = randomZ(N)
    caPubkey = caPrivkey * G
    idText = "alice"
    k_a = randomZ(N)
    r_a = k_a * G

    authoritykey = int(randomZ(N))
    (r, cert) = ecqv_anony_sign(idText, r_a, caPrivkey,authoritykey)

    (d_a, validate) = ecqv_anony_validate(idText, k_a, r, cert, caPubkey)

    Q_a = ecqv_anony_recoverPubkey(idText, cert, caPubkey)

    extractid = ecqv_anony_recoverRealid(cert, authoritykey)
    assert extractid == idText, "error"




