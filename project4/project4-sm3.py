import struct
import math
import time
import os
import sys
from typing import List, Tuple

# ----------------------
# SM3: 基本操作与实现
# ----------------------

def _rotl(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def _P0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _P1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def _FF(j: int, x: int, y: int, z: int) -> int:
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | (x & z) | (y & z)

def _GG(j: int, x: int, y: int, z: int) -> int:
    if 0 <= j <= 15:
        return x ^ y ^ z
    else:
        return (x & y) | ((~x) & z)

# T_j constants
_T = [0x79cc4519 if j <= 15 else 0x7a879d8a for j in range(64)]

# Compression function - processes one 512-bit block (16 words)
def _sm3_compress(v: List[int], block: bytes) -> List[int]:
    # v: 8-word state (list of 32-bit ints)
    # block: 64 bytes
    W = [0] * 68
    W1 = [0] * 64

    # message extension
    for i in range(16):
        W[i] = struct.unpack(">I", block[4*i:4*i+4])[0]
    for j in range(16, 68):
        x = W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)
        W[j] = (_P1(x) ^ _rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF
    for j in range(64):
        W1[j] = W[j] ^ W[j+4]

    A, B, C, D, E, F, G, H = v

    for j in range(64):
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(_T[j], j)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_FF(j, A, B, C) + D + SS2 + W1[j]) & 0xFFFFFFFF
        TT2 = (_GG(j, E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _P0(TT2)

    v_out = [
        A ^ v[0],
        B ^ v[1],
        C ^ v[2],
        D ^ v[3],
        E ^ v[4],
        F ^ v[5],
        G ^ v[6],
        H ^ v[7],
    ]
    return [x & 0xFFFFFFFF for x in v_out]

class SM3:
    IV = [
        0x7380166f,
        0x4914b2b9,
        0x172442d7,
        0xda8a0600,
        0xa96f30bc,
        0x163138aa,
        0xe38dee4d,
        0xb0fb0e4e,
    ]

    def __init__(self):
        self._buf = b""
        self._length = 0  # bits
        self._V = SM3.IV.copy()

    def update(self, data: bytes):
        self._buf += data
        self._length += len(data) * 8
        while len(self._buf) >= 64:
            block = self._buf[:64]
            self._buf = self._buf[64:]
            self._V = _sm3_compress(self._V, block)

    def digest(self) -> bytes:
        # padding
        l = self._length
        buf = self._buf + b'\x80'
        # pad with zeros until length in bytes ≡ 56 mod 64
        pad_len = (56 - (len(buf) % 64)) % 64
        buf += b'\x00' * pad_len
        buf += struct.pack(">Q", l)
        V = self._V.copy()
        # process final blocks
        i = 0
        while i < len(buf):
            V = _sm3_compress(V, buf[i:i+64])
            i += 64
        # produce digest
        return b''.join(struct.pack(">I", x) for x in V)

    def hexdigest(self) -> str:
        return self.digest().hex()

    # convenience
    @staticmethod
    def hash(data: bytes) -> bytes:
        h = SM3()
        h.update(data)
        return h.digest()

    @staticmethod
    def hexdigest_static(data: bytes) -> str:
        return SM3.hash(data).hex()

# ----------------------
# Length-Extension Attack 演示
# ----------------------

def digest_to_state(digest: bytes) -> List[int]:
    if len(digest) != 32:
        raise ValueError("SM3 digest must be 32 bytes")
    return list(struct.unpack(">8I", digest))

def sm3_length_extension(orig_digest: bytes, orig_message_len_bytes: int, suffix: bytes) -> Tuple[bytes, bytes]:
    lbits = orig_message_len_bytes * 8
    pad = b'\x80'
    pad_len = (56 - ((orig_message_len_bytes + 1) % 64)) % 64
    pad += b'\x00' * pad_len
    pad += struct.pack(">Q", lbits)
    data_to_process = suffix
    V = digest_to_state(orig_digest)
    sm = SM3()
    sm._V = V.copy()
    sm._length = (orig_message_len_bytes + len(pad)) * 8
    sm._buf = b''
    sm.update(data_to_process)
    forged_digest = sm.digest()
    forged_message_tail = pad + suffix
    return forged_digest, forged_message_tail



def leaf_hash(data: bytes) -> bytes:
    return SM3.hash(b'\x00' + data)

def node_hash(left: bytes, right: bytes) -> bytes:
    return SM3.hash(b'\x01' + left + right)

class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        # leaves: list of raw leaf data (bytes)
        self.n = len(leaves)
        # compute hashed leaves
        self.leaf_hashes = [leaf_hash(x) for x in leaves]
        # build tree levels bottom-up; store as list of levels where level[0] is leaves
        self.levels = []
        self._build_tree()

    def _build_tree(self):
        level = self.leaf_hashes.copy()
        self.levels.append(level)
        while len(level) > 1:
            next_level = []
            it = iter(level)
            for i in range(0, len(level), 2):
                left = level[i]
                if i+1 < len(level):
                    right = level[i+1]
                else:
                    # duplicate last
                    right = left
                next_level.append(node_hash(left, right))
            level = next_level
            self.levels.append(level)

    def root(self) -> bytes:
        return self.levels[-1][0] if self.levels else b''

    def get_inclusion_proof(self, index: int) -> List[bytes]:
        if index < 0 or index >= self.n:
            raise IndexError("leaf index out of range")
        proof = []
        idx = index
        for level in self.levels[:-1]:
            # sibling index:
            if idx % 2 == 0:
                sib_idx = idx + 1
            else:
                sib_idx = idx - 1
            if sib_idx >= len(level):
                # sibling absent (we duplicated last), use the node itself
                proof.append(level[idx])
            else:
                proof.append(level[sib_idx])
            idx //= 2
        return proof

    @staticmethod
    def verify_inclusion(leaf: bytes, index: int, proof: List[bytes], root: bytes, total_leaves: int) -> bool:
        cur = leaf_hash(leaf)
        idx = index
        for sib in proof:
            if idx % 2 == 0:
                cur = node_hash(cur, sib)
            else:
                cur = node_hash(sib, cur)
            idx //= 2
        return cur == root

    def get_leaf_count(self) -> int:
        return self.n
# ----------------------
# Demo / unit tests
# ----------------------
def _demo_small():
    print("=== SM3 demo ===")
    data = b"abc"
    print("SM3('abc') =", SM3.hexdigest_static(data))

    print("\n=== Length-extension demo ===")
    orig = b"secret_message"
    orig_digest = SM3.hash(orig)
    print("orig len:", len(orig))
    suffix = b";admin=true"
    forged_digest, tail = sm3_length_extension(orig_digest, len(orig), suffix)
    true = SM3.hash(orig + tail)
    print("forged == true?", forged_digest == true)

    print("\n=== Merkle demo (small) ===")
    leaves = [f"leaf{i}".encode() for i in range(7)]
    T = MerkleTree(leaves)
    r = T.root()
    print("root:", r.hex())
    idx = 3
    proof = T.get_inclusion_proof(idx)
    ok = MerkleTree.verify_inclusion(leaves[idx], idx, proof, r, T.get_leaf_count())
    print("inclusion verify for idx", idx, ok)

def _demo_100k(n=100_000):
    print(f"\n=== Building Merkle tree with {n} leaves (timing) ===")
    # use simple deterministic leaves to avoid randomness overhead
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    t0 = time.perf_counter()
    T = MerkleTree(leaves)
    t1 = time.perf_counter()
    print(f"Built tree with {n} leaves in {t1-t0:.3f}s; root len={len(T.root())} bytes")
    # sample proofs
    for idx in [0, n//2, n-1]:
        t0 = time.perf_counter()
        proof = T.get_inclusion_proof(idx)
        t1 = time.perf_counter()
        ok = MerkleTree.verify_inclusion(leaves[idx], idx, proof, T.root(), n)
        print(f"idx {idx}: proof len {len(proof)}, verify={ok}, gen_time={t1-t0:.4f}s")

if __name__ == "__main__":
    _demo_small()
