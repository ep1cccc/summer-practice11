import random
import hashlib
from gmpy2 import mpz, invert, powmod, is_prime

# ----------------------------
# 1. SM2基础参数与椭圆曲线运算
# ----------------------------
class SM2Curve:
    """SM2椭圆曲线参数（国密标准GM/T 0003.1-2012）"""
    def __init__(self):
        # 素数域参数
        self.p = mpz("0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
        self.a = mpz("0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
        self.b = mpz("0x28E9FA9E9D9F5E344D5A9E4BCF6509A5D9F6AC28EF3412673B43F5ED563B4A")
        # 基点G
        self.Gx = mpz("0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
        self.Gy = mpz("0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
        self.G = (self.Gx, self.Gy)
        # 阶数
        self.n = mpz("0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")
        self.h = mpz(1)  # 余因子

    def is_on_curve(self, P):
        """验证点是否在椭圆曲线上"""
        if P is None:
            return False  # 无穷远点
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def point_add(self, P, Q):
        """椭圆曲线点加法 P + Q"""
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            return None  # 无穷远点（互为逆元）

        if x1 != x2:
            lam = (y2 - y1) * invert(x2 - x1, self.p) % self.p
        else:
            # 点 doubling
            lam = (3 * x1 * x1 + self.a) * invert(2 * y1, self.p) % self.p

        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def point_mul(self, P, k):
        """椭圆曲线标量乘法 k*P（使用W-NAF优化）"""
        k = mpz(k)
        k = k % self.n  # 阶数取模
        result = None
        current = P

        # 二进制展开法（简化版，实际可优化为W-NAF）
        while k > 0:
            if k & 1:
                result = self.point_add(result, current)
            current = self.point_add(current, current)  # 2*current
            k >>= 1
        return result

    def generate_key_pair(self):
        """生成密钥对 (私钥d, 公钥P=d*G)"""
        d = mpz(random.randint(1, int(self.n - 1)))
        P = self.point_mul(self.G, d)
        return d, P


# ----------------------------
# 2. SM2签名与验证
# ----------------------------
def sm3_hash(data):
    """简化版SM3哈希（实际应用需用标准实现）"""
    return hashlib.sha256(data).digest()  # 此处用SHA256模拟，实际需替换为标准SM3

class SM2:
    def __init__(self):
        self.curve = SM2Curve()

    def sign(self, d, msg, k=None):
        """SM2签名: 生成 (r, s)
        d: 私钥
        msg: 消息字节流
        k: 随机数（默认自动生成）
        """
        curve = self.curve
        n = curve.n
        G = curve.G

        # 生成随机数k
        if k is None:
            k = mpz(random.randint(1, int(n - 1)))
        else:
            k = mpz(k)  # 允许指定k（用于POC测试）

        # 计算k*G
        K = curve.point_mul(G, k)
        x1, y1 = K

        # 计算r = (e + x1) mod n，其中e是消息哈希的整数形式
        e = mpz(int.from_bytes(sm3_hash(msg), byteorder='big'))
        r = (e + x1) % n
        if r == 0 or r + k == n:
            raise ValueError("签名失败，需重新生成k")

        # 计算s = (invert(1+d, n) * (k - r*d)) mod n
        s = (invert(1 + d, n) * (k - r * d)) % n
        if s == 0:
            raise ValueError("签名失败，需重新生成k")
        return (r, s)

    def verify(self, P, msg, sig):
        """SM2验证: 验证签名 (r, s) 是否有效
        P: 公钥（点坐标）
        msg: 消息字节流
        sig: (r, s) 签名
        """
        curve = self.curve
        n = curve.n
        G = curve.G
        r, s = sig

        # 验证参数范围
        if r < 1 or r >= n or s < 1 or s >= n:
            return False

        # 计算e = H(msg)
        e = mpz(int.from_bytes(sm3_hash(msg), byteorder='big'))

        # 计算t = (r + s) mod n
        t = (r + s) % n
        if t == 0:
            return False

        # 计算u1 = e * t mod n, u2 = r * t mod n
        u1 = (e * t) % n
        u2 = (r * t) % n

        # 计算u1*G + u2*P
        U1 = curve.point_mul(G, u1)
        U2 = curve.point_mul(P, u2)
        X = curve.point_add(U1, U2)
        if X is None:
            return False
        x1, y1 = X

        # 验证r == (e + x1) mod n
        return (e + x1) % n == r


# ----------------------------
# 3. 签名算法误用POC（固定k导致私钥泄露）
# ----------------------------
def poc_fixed_k_leak():
    print("=== 固定随机数k导致私钥泄露POC ===")
    sm2 = SM2()
    curve = sm2.curve

    # 生成合法密钥对
    d, P = curve.generate_key_pair()
    print(f"真实私钥: {hex(d)}")

    # 固定随机数k（模拟误用）
    fixed_k = mpz(0x123456789ABCDEF)  # 攻击者不知道的固定k

    # 对两个不同消息签名
    msg1 = b"message1"
    msg2 = b"message2"
    sig1 = sm2.sign(d, msg1, k=fixed_k)
    sig2 = sm2.sign(d, msg2, k=fixed_k)
    r1, s1 = sig1
    r2, s2 = sig2

    # 攻击者仅已知：两个签名、两个消息、公钥P
    e1 = mpz(int.from_bytes(sm3_hash(msg1), byteorder='big'))
    e2 = mpz(int.from_bytes(sm3_hash(msg2), byteorder='big'))
    n = curve.n

    # 推导私钥d：d = (s1 - s2) * inv(r2 - r1) mod n
    numerator = (s1 - s2) % n
    denominator = (r2 - r1) % n
    if denominator == 0:
        print("无法恢复（分母为0）")
        return

    d_recover = (numerator * invert(denominator, n)) % n
    print(f"恢复私钥: {hex(d_recover)}")
    print(f"恢复成功: {d_recover == d}")


# ----------------------------
# 4. 伪造中本聪签名（已知公钥情况下构造签名）
# ----------------------------
def forge_nakamoto_signature(public_key):
    print("\n=== 伪造中本聪签名 ===")
    sm2 = SM2()
    curve = sm2.curve
    n = curve.n
    G = curve.G
    P = public_key  # 中本聪公钥（假设已知）

    # 构造参数：选择s=1，t=1，反推r和消息e
    s = mpz(1)
    t = (r + s) % n  # 先假设r，后续修正
    while True:
        # 随机选择r（确保t≠0）
        r = mpz(random.randint(1, int(n - 1)))
        t = (r + s) % n
        if t == 0:
            continue

        # 计算u1 = e*t mod n，u2 = r*t mod n
        # 目标：u1*G + u2*P 的x坐标满足 x1 = (r - e) mod n
        # 反推e = (r - x1) mod n，其中x1是u1G + u2P的x坐标
        # 令u1 = k，u2 = 1，则e = (r - x1)/t mod n（简化构造）
        k = mpz(random.randint(1, int(n - 1)))
        u1 = k
        u2 = mpz(1)
        U1 = curve.point_mul(G, u1)
        U2 = curve.point_mul(P, u2)
        X = curve.point_add(U1, U2)
        if X is None:
            continue
        x1, y1 = X

        # 构造e
        e = (r - x1) * invert(t, n) % n
        if e <= 0:
            continue

        # 验证是否满足u1 = e*t mod n
        if (e * t) % n != u1:
            continue

        # 生成伪造消息（e的字节形式）
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        forged_msg = e_bytes  # 伪造的消息
        forged_sig = (r, s)

        # 验证伪造签名
        if sm2.verify(P, forged_msg, forged_sig):
            print(f"伪造签名成功: r={hex(r)}, s={hex(s)}")
            print(f"伪造消息哈希: {e_bytes.hex()}")
            return forged_msg, forged_sig

    return None, None


# ----------------------------
# 测试主函数
# ----------------------------
if __name__ == "__main__":
    # 测试基础签名与验证
    sm2 = SM2()
    d, P = sm2.curve.generate_key_pair()
    msg = b"test sm2 signature"
    sig = sm2.sign(d, msg)
    print(f"\n基础签名验证: {sm2.verify(P, msg, sig)}")

    # 测试固定k导致私钥泄露
    poc_fixed_k_leak()

    # 测试伪造中本聪签名（使用随机生成的"中本聪公钥"）
    _, nakamoto_pub = sm2.curve.generate_key_pair()  # 模拟中本聪公钥
    forge_nakamoto_signature(nakamoto_pub)