from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
M = b'arbitrary receipt forged without any secret'
sig = open('/tmp/small-order-matrix/sig-identity.bin','rb').read()
for name, hexkey in [('identity(order1)','01'+'00'*31), ('order2(0,-1)','ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')]:
    A = bytes.fromhex(hexkey)
    pub = Ed25519PublicKey.from_public_bytes(A)  # 若构造即拒绝则打 ERR
    try:
        pub.verify(sig, M)
        print(f'python-cryptography {name}: ❌ ACCEPTED')
    except InvalidSignature:
        print(f'python-cryptography {name}: ✅ rejected')
    except Exception as e:
        print(f'python-cryptography {name}: ✅ rejected at import ({type(e).__name__})')
