import random
import hashlib
from typing import List, ByteString

# 协议参数配置
k = 3  # 哈希函数数量（平衡假阳性率和性能）
M = 10 ** 4  # 布隆过滤器大小（模值）
p = 10 ** 9 + 7  # 大素数，用于模运算确保安全性


class Server:
    """服务器端实现：存储泄露密码的加密表示，响应客户端查询"""

    def __init__(self, leaked_passwords: List[ByteString]):
        self.k = k
        self.M = M
        self.p = p
        # 初始化k个布隆过滤器表，存储加密后的密码份额
        self.tables = [[0 for _ in range(M)] for _ in range(k)]
        self.leaked_passwords = leaked_passwords
        self._preprocess_leaked_passwords()

    def _hash_func(self, j: int, password: ByteString) -> int:
        """第j个哈希函数：将密码映射到[0, M)区间"""
        salt = str(j).encode()  # 每个哈希函数使用不同盐值
        hash_bytes = hashlib.sha256(salt + password).digest()
        return int.from_bytes(hash_bytes, byteorder='big') % self.M

    def _preprocess_leaked_passwords(self):
        """预处理泄露密码：为每个密码生成随机份额并填充到布隆过滤器"""
        for password in self.leaked_passwords:
            # 为每个泄露密码生成一个随机秘密值s（模p）
            s = random.randint(1, self.p - 1)
            # 对每个哈希函数，更新对应布隆过滤器位置
            for j in range(self.k):
                idx = self._hash_func(j, password)
                self.tables[j][idx] = (self.tables[j][idx] + s) % self.p

    def query(self, b_list: List[int]) -> int:
        """响应客户端查询：返回对应位置的份额总和"""
        if len(b_list) != self.k:
            raise ValueError(f"需要{k}个查询参数，实际收到{len(b_list)}个")

        total = 0
        for j in range(self.k):
            # 确保索引在有效范围内
            b_j = b_list[j] % self.M
            total = (total + self.tables[j][b_j]) % self.p
        return total


class Client:
    """客户端实现：检查密码是否泄露，不泄露原始密码"""

    def __init__(self):
        self.k = k
        self.M = M
        self.p = p

    def _hash_func(self, j: int, password: ByteString) -> int:
        """与服务器一致的哈希函数（确保映射结果相同）"""
        salt = str(j).encode()
        hash_bytes = hashlib.sha256(salt + password).digest()
        return int.from_bytes(hash_bytes, byteorder='big') % self.M

    def check_password(self, password: ByteString, server: Server) -> bool:
        """检查密码是否在泄露列表中（概率性结果）"""
        # 1. 计算密码在每个哈希函数下的映射值x_j
        x_list = [self._hash_func(j, password) for j in range(self.k)]

        # 2. 生成随机份额a_j，计算查询参数b_j = (x_j - a_j) mod M
        a_list = [random.randint(0, self.p - 1) for _ in range(self.k)]
        b_list = [(x_list[j] - a_list[j]) % self.M for j in range(self.k)]

        # 3. 向服务器查询并获取结果
        server_sum = server.query(b_list)

        # 4. 计算本地份额总和，验证是否匹配
        client_sum = sum(a_list) % self.p
        total = (client_sum + server_sum) % self.p

        # 5. 若总和为0，大概率密码已泄露（基于随机份额的概率特性）
        return total == 0


def demo():
    """演示协议运行流程"""
    # 模拟泄露的密码列表（实际中可能包含数百万个密码）
    leaked_passwords = [
        b"password123", b"123456", b"qwerty",
        b"admin", b"letmein", b"111111"
    ]

    # 初始化服务器
    server = Server(leaked_passwords)
    # 初始化客户端
    client = Client()

    # 测试用例：包含泄露和未泄露的密码
    test_passwords = [
        b"password123",  # 已泄露
        b"123456",  # 已泄露
        b"secure_123!",  # 未泄露
        b"qwerty",  # 已泄露
        b"mysecret",  # 未泄露
        b"letmein"  # 已泄露
    ]

    # 对每个密码进行多次检测（因为结果是概率性的）
    print("密码检测结果（多次检测以降低误差）：")
    print("-" * 60)
    for pwd in test_passwords:
        # 多次检测提高准确性
        trials = 100
        positive_count = sum(1 for _ in range(trials) if client.check_password(pwd, server))
        leaked = positive_count > trials * 0.1  # 阳性率超过10%则判断为泄露
        print(
            f"密码: {pwd.decode():<12} 阳性次数: {positive_count:3d}/{trials}  判定: {'已泄露' if leaked else '未泄露'}")


if __name__ == "__main__":
    demo()