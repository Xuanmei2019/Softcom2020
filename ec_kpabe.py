'''
An ECC-based access control scheme with lightweight decryption and conditional authentication for data sharing in vehicular networks

| Published in: Soft computing
| Available From: https://link.springer.com/article/10.1007/s00500-020-05117-x
| Notes: 

* type:           key-policy attribute-based encryption (public key)
* setting:        No Pairing

:Authors:    Qin
:Date:       
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair ,extract_key
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.toolbox.ABEnc import ABEnc
from charm.core.math.pairing import hashPair,serialize

debug = False
class EcKPabe(ABEnc):
    def __init__(self, groupObj, verbose=False):
        ABEnc.__init__(self)
        global group, util
        group = groupObj
        util = SecretUtil(group, verbose)     
    def setup(self, attributes):
        s = group.random(ZR)
        g = group.random(G1)  

        self.attributeSecrets = {}
        self.attribute = {}
        for attr in attributes:
            si = group.random(ZR)
            self.attributeSecrets[attr] = si
            self.attribute[attr] = g**si
        return (g**s, s, g) # (pk, mk)
    
    def register(self,g,s):
        k = group.random(ZR)  
        R = g**k        
        k = group.random(ZR)
        P = R + g**k
        Cert = P
        e = hash(Cert)
        r = ((e * k)+s)
        d = ((e * k)+r)
        Q = g**d
        return (r,Cert,d,Q)
       

    def encrypt(self, pk, M, attr_list): 
        if debug: print('Encryption Algorithm...')
        k = group.random(ZR);
        Cs = pk ** k
        
        Ci = {}
        for attr in attr_list:
            Ci[attr] = self.attribute[attr] ** k
        
        symcrypt = SymmetricCryptoAbstraction(hashPair(Cs))
        C = symcrypt.encrypt(M)
        # HMAC
        # from charm.toolbox.symcrypto import MessageAuthenticator
        # m = MessageAuthenticator(extract_key(key))
        # AuthenticatedMessage = m.mac('Hello World')
        return { 'C': C, 'Ci': Ci,'attributes': attr_list }


    def keygen(self, policy_str, mk,Q_u):
        policy = util.createPolicy(policy_str)
        attr_list = util.getAttributeList(policy)    
        s = mk
        shares = util.calculateSharesDict(s, policy)
        
        d = {}
        D = { 'policy': policy_str, 'Du': d }
        for x in attr_list:
            y = util.strip_index(x)
            d[y] = shares[x]/(self.attributeSecrets[y])
            if debug: print(str(y) + " d[y] " + str(d[y]))
        if debug: print("Access Policy for key: %s" % policy)
        if debug: print("Attribute list: %s" % attr_list)

        return D
    
    def tokengen(self, attr_key,  d_u, Q_cloud):
        h = group.random(ZR) # pairing.element
        tk = {}
        policy_str = util.createPolicy(attr_key['policy'])
        attr_list = util.getAttributeList(policy_str)
        tmp = int.from_bytes(hashPair(Q_cloud ** d_u),'big')  # python 3.X  bytes to int
        sharekey =  group.init(ZR,tmp)
        for x in attr_list:
            y = util.strip_index(x)           
            tk[y] = attr_key['Du'][y] / h  + sharekey
            if debug: print(str(y) + " tk[y] " + str(tk[y]))
        if debug: print("Access Policy for key: %s" % attr_key['policy'])
        if debug: print("Attribute list: %s" % attr_list)    
        TK = {'policy': attr_key['policy'], 'token':tk}
        return TK, h

    
    def CLoud_decrypt(self, C, TK, d_cloud,  Q_u):
        policy = util.createPolicy(TK['policy'])
        attrs = util.prune(policy, C['attributes'])
        if attrs == False:
            return False
        coeff = util.getCoefficients(policy)
        
        Z = {}
        prodT = 1
        tmp = int.from_bytes(hashPair(Q_u ** d_cloud),'big')  # python 3.X  bytes to int
        sharekey = group.init(ZR,tmp)
        for i in range(len(attrs)):
            x = attrs[i].getAttribute()
            y = attrs[i].getAttributeAndIndex()
            
            Z[y] = C['Ci'][x] ** (TK['token'][x] - sharekey)
            prodT *= Z[y] ** coeff[y]
        return prodT

    def decrypt(self, C, prodT,h):
        symcrypt = SymmetricCryptoAbstraction(hashPair(prodT*h))    
        return symcrypt.decrypt(C['C'])


def main():
    groupObj = PairingGroup('MNT224')
    ec_kpabe = EcKPabe(groupObj)
    attributes = [ 'ONE', 'TWO', 'THREE', 'FOUR' ]
    (pk, mk, g) = ec_kpabe.setup(attributes)   
    
    (r_u,Cert_u,d_u,Q_u)= ec_kpabe.register(g,mk)  #DU
    (r_A,Cert_A,d_A,Q_A)= ec_kpabe.register(g,mk)  #AA
    (r_cloud,Cert_cloud,d_cloud,Q_cloud)= ec_kpabe.register(g,mk)    #CSP

    # policy = '(ONE or THREE) and (THREE or TWO)'
    policy = 'THREE and (ONE or TWO)'
    msg = b"Some Random Message"

    if debug: print("Encrypt under these attributes: ", attributes)
    ciphertext = ec_kpabe.encrypt(Q_A, msg, attributes)
    if debug: print(ciphertext)
    
    attrkey = ec_kpabe.keygen(policy, d_A, Q_u)

    (token,h) = ec_kpabe.tokengen( attrkey, d_u,  Q_cloud)

    prodT = ec_kpabe.CLoud_decrypt(ciphertext, token, d_cloud,  Q_u)

    rec_msg = ec_kpabe.decrypt(ciphertext,prodT,h)
    assert rec_msg
    if debug: print("rec_msg=%s" % str(rec_msg))

    assert msg == rec_msg
    if debug: print("Successful Decryption!")
