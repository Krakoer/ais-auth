from pypbc import *
from dataclasses import dataclass, fields
from hashlib import sha256
import pathlib
#############################################
#					Utilities			    #
#############################################

def as_dict(obj):
    res = {}
    for field in fields(obj):
        res[field.name] = str(getattr(obj, field.name))
    return res

def to_int(el):
    return int(str(el), 16)

def to_bytes(el):
    return bytes.fromhex(str(el))

def is_sym(p : Pairing):
    a = Element.random(p, G1)
    b = Element.random(p, G1)
    return p.apply(a, b) == p.apply(b, a)

@dataclass
class PublicParameters:
    # (G 1 , G 2 , q, e, P, P pub , H 1 , g = e(P, P ))
    P: Element
    P1: Element
    P2: Element
    g: Element

@dataclass
class MasterPrivateKey:
    si: Element

@dataclass
class PublicKey:
    Pid: Element
    Rid: Element

@dataclass
class PrivateKey:
    xid: Element
    sid: Element

class TsaiKGC:
    pairing:Pairing = None
    public_params:PublicParameters = None
    private_key: MasterPrivateKey = None
    
    def __init__(self, param_path):
        with open(param_path, 'r') as f:
            params = Parameters(f.read())
        self.pairing = Pairing(params)

    def master_keygen(self):
        """
        Generates the master public and private keys
        returns two dicts : public key and private key with keys P, P1, P2 and g for the first one and si for the second one
        """
        P = Element.random(self.pairing, G1)
        s = Element.random(self.pairing, Zr)
        P1 = Element(self.pairing, G1, P*s)
        si = Element(self.pairing, Zr, s**-1)
        P2 = Element(self.pairing, G1, P*si)
        g = self.pairing.apply(P, P)
        self.public_params = PublicParameters(P, P1, P2, g)
        self.private_key = MasterPrivateKey(si)

        return as_dict(self.public_params), as_dict(self.private_key)

    def set_public_params(self, params):
        """
        Set public params from a dict
        """
        self.public_params = PublicParameters(
            Element(self.pairing, G1, params["P"]),
            Element(self.pairing, G1, params["P1"]),
            Element(self.pairing, G1, params["P2"]),
            Element(self.pairing, GT, params["g"]),
        )
    
    def set_private_key(self, key):
        """
        Set private key from dict
        """
        self.private_key = MasterPrivateKey(
            Element(self.pairing, Zr, int(key["si"], 16))
        )


    def partial_keygen(self, _id : bytes):
        """
        Generate partial keys from ID
        Returns a dict with sid and Rid
        """
        if self.public_params == None:
            raise Exception("Public params not initialized")
        if self.private_key == None:
            raise Exception("Private key not initialized")
        P1 = Element(self.pairing, G1, self.public_params.P1)
        si = Element(self.pairing, Zr, self.private_key.si)
        rid = Element.random(self.pairing, Zr)

        Rid = P1*rid

        h = sha256(_id+to_bytes(P1)+to_bytes(Rid)).digest()
        hid = Element.from_hash(self.pairing, Zr, h)
        sid = Element(self.pairing, Zr, rid + si*hid)

        return {"sid":str(sid), "Rid": str(Rid)}

class TsaiUser:
    pairing : Pairing = None
    private_key : PrivateKey = None
    public_key : PublicKey = None
    public_params: PublicParameters = None
    def __init__(self, param_path):
        with open(param_path, 'r') as f:
            params = Parameters(f.read())
        self.pairing = Pairing(params)
    
    def set_public_params(self, pp):
        """
        Set public params from Public Parameters object
        """
        self.public_params = pp

    def public_params_from_dict(self, pp):
        """
        Set public params from dict
        """
        self.public_params = PublicParameters(
            Element(self.pairing, G1, pp["P"]),
            Element(self.pairing, G1, pp["P1"]),
            Element(self.pairing, G1, pp["P2"]),
            Element(self.pairing, GT, pp["g"]),
        )

    def generate_keys(self, sid, Rid):
        """
        Generates full private/public keys from partial ones
        Returns two dict : private and public keys
        """
        xid = Element.random(self.pairing, Zr)
        Pid = Element(self.pairing, G1, self.public_params.P1*xid)
        self.private_key = PrivateKey(xid, Element(self.pairing, Zr, int(sid, 16)))
        self.public_key = PublicKey(Pid, Element(self.pairing, G1, Rid))

        return as_dict(self.public_key), as_dict(self.private_key)
        
    def set_keys(self, private, public):
        """
        Set private and public key from dict
        """
        self.private_key = PrivateKey(
            Element(self.pairing, Zr, int(private["xid"], 16)), 
            Element(self.pairing, Zr, int(private["sid"], 16))
        )
        self.public_key = PublicKey(
            Element(self.pairing, G1, public["Pid"]), 
            Element(self.pairing, G1, public["Rid"])
        )

    def sign(self, message : bytes):
        if self.public_key == None:
            raise Exception("Public key is not initialized")
        if self.private_key == None:
            raise Exception("Private key is not initialized")
        if self.public_params == None:
            raise Exception("Public params is not initialized")
        kid_h = sha256(message+to_bytes(self.public_key.Rid)+to_bytes(self.public_key.Pid)).digest()
        kid = Element.from_hash(self.pairing, Zr, kid_h)

        sign = self.public_params.P2*((kid * self.private_key.sid + self.private_key.xid)**-1)
        
        return to_bytes(sign)

    def verify(self, message, signature, identity, publickey_dict):
        """
        Args:
            - message in bytes
            - signature in bytes
            - identity in bytes
            - public key as a dict
        """
        if self.public_params == None:
            raise Exception("Public params is not initialized")

        publickey = PublicKey(
            Element(self.pairing, G1, publickey_dict["Pid"]),
            Element(self.pairing, G1, publickey_dict["Rid"]),
        )

        h = sha256(identity+to_bytes(self.public_params.P1)+to_bytes(publickey.Rid)).digest()
        hid = Element.from_hash(self.pairing, Zr, h)
        print(f"identoty from vrfy : {identity}")

        kid_h = sha256(message+to_bytes(publickey.Rid)+to_bytes(publickey.Pid)).digest()
        kid = Element.from_hash(self.pairing, Zr, kid_h)
        print(f"kid from vrfy : {kid}")
        signP = Element(self.pairing, G1, (publickey.Rid + self.public_params.P*hid)*kid + publickey.Pid)
        signature = Element(self.pairing, G1, signature.hex())

        return self.public_params.g == self.pairing.apply(signP, signature)

def test():
    from importlib.metadata import version
    print(f"Using pypbc version {version('pypbc')}")
    param_path = f"{pathlib.Path(__file__).parent.resolve()}/a.param"
    KGC = TsaiKGC(param_path)
    public_params = KGC.master_keygen()

    c1 = TsaiUser(param_path)
    c2 = TsaiUser(param_path)

    c1.set_public_params(public_params)
    c2.set_public_params(public_params)

    sid, Rid = KGC.partial_keygen(b"888888888")
    c1.generate_keys(sid, Rid)
    sid, Rid = KGC.partial_keygen(b"999999999")
    c2.generate_keys(sid, Rid)

    message = b"Coucou !"

    s = c1.sign(message)
    if c2.verify(b"Coucou !", str(s), b"888888888", c1.public_key):
        print("Check OK!")
    else:
        print("Check failed")

if __name__=="__main__":
    test()
