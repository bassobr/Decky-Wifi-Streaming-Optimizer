"""Pure-Python Ed25519 (RFC 8032), extended-coordinate variant.

Vendored because neither SteamOS/Bazzite nor Decky's bundled Python ship an
Ed25519 implementation, and release-signature verification (see minisign.py)
must work on the device with stdlib only. The same code signs in CI so signer
and verifier can never drift apart. Correctness is pinned by the official
RFC 8032 test vectors in tests/test_main.py.

NOT constant-time: fine for verification (no secret on the device) and for
CI signing (no remote timing observer); never use it to handle long-term
secrets on user devices.
"""

import hashlib

# Curve constants (edwards25519, RFC 8032 section 5.1)
p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493  # group order
d = -121665 * pow(121666, p - 2, p) % p
modp_sqrt_m1 = pow(2, (p - 1) // 4, p)


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % q


# Points are (X, Y, Z, T) in extended homogeneous coordinates with
# x = X/Z, y = Y/Z, x*y = T/Z. The addition formula below is complete for
# edwards25519, so it also handles doubling and the neutral element.

def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    # x1/z1 == x2/z2 and y1/z1 == y2/z2
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_g_y = 4 * pow(5, p - 2, p) % p
_g_x = _recover_x(_g_y, 0)
G = (_g_x, _g_y, 1, _g_x * _g_y % p)


def _point_compress(P) -> bytes:
    zinv = pow(P[2], p - 2, p)
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("bad seed length (expected 32 bytes)")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def secret_to_public(secret: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed."""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, G))


def sign(secret: bytes, msg: bytes) -> bytes:
    """Sign msg with the 32-byte seed; returns the 64-byte signature."""
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, G))
    r = _sha512_modq(prefix + msg)
    Rs = _point_compress(_point_mul(r, G))
    h = _sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """Verify a 64-byte signature over msg against a 32-byte public key."""
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _sha512_modq(Rs + public + msg)
    sB = _point_mul(s, G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
