import os
import json
import subprocess
from web3 import Web3
from circomlibjs import poseidon  # 需要安装circomlibjs

# 配置参数
CIRCUIT_NAME = "poseidon2"
INPUT_FILE = "input.json"
WITNESS_FILE = "witness.wtns"
ZKEY_FILE = f"{CIRCUIT_NAME}.zkey"
VK_FILE = f"{CIRCUIT_NAME}_vk.json"
PROOF_FILE = "proof.json"
PUBLIC_FILE = "public.json"


def clean_up():
    """清理之前的文件"""
    files = [
        f"{CIRCUIT_NAME}.r1cs",
        f"{CIRCUIT_NAME}.sym",
        INPUT_FILE,
        WITNESS_FILE,
        ZKEY_FILE,
        VK_FILE,
        PROOF_FILE,
        PUBLIC_FILE,
        "circuit_final.zkey"
    ]

    for file in files:
        if os.path.exists(file):
            os.remove(file)


def compile_circuit():
    """编译Circom电路"""
    print("编译电路...")
    result = subprocess.run(
        ["circom", f"{CIRCUIT_NAME}.circom", "--r1cs", "--wasm", "--sym"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("编译失败:")
        print(result.stderr)
        exit(1)
    print("电路编译成功")


def generate_input():
    """生成输入数据"""
    print("生成输入数据...")

    # 隐私输入 (哈希原象)
    secret_inputs = [12345, 67890]

    # 计算预期的哈希值 (使用circomlibjs的Poseidon实现)
    # 注意: 实际应用中应确保与Circom实现使用相同的参数
    hash_value = poseidon.poseidon(secret_inputs, 2, 3, 5)  # (inputs, t, n, d)

    # 准备输入文件
    input_data = {
        "expectedHash": hash_value,
        "input": secret_inputs
    }

    with open(INPUT_FILE, "w") as f:
        json.dump(input_data, f)

    return secret_inputs, hash_value


def generate_witness():
    """生成见证"""
    print("生成见证...")
    result = subprocess.run(
        [f"./{CIRCUIT_NAME}_js/generate_witness", f"./{CIRCUIT_NAME}_js/{CIRCUIT_NAME}.wasm", INPUT_FILE, WITNESS_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("生成见证失败:")
        print(result.stderr)
        exit(1)
    print("见证生成成功")


def setup_trusted_setup():
    """执行可信设置"""
    print("执行可信设置...")

    # 第一步: 生成初始zkey
    result = subprocess.run(
        ["snarkjs", "groth16", "setup", f"{CIRCUIT_NAME}.r1cs", "pot12_final.ptau", ZKEY_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("初始zkey生成失败:")
        print(result.stderr)
        exit(1)

    # 第二步: 贡献随机数 (在实际环境中，这应该由多个参与者完成)
    result = subprocess.run(
        ["snarkjs", "zkey", "contribute", ZKEY_FILE, "circuit_final.zkey", "--name", "First contribution", "-v",
         "123456"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("zkey贡献失败:")
        print(result.stderr)
        exit(1)

    # 导出验证密钥
    result = subprocess.run(
        ["snarkjs", "zkey", "export", "verifier", "circuit_final.zkey", VK_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("验证密钥导出失败:")
        print(result.stderr)
        exit(1)

    print("可信设置完成")


def generate_proof():
    """生成证明"""
    print("生成证明...")
    result = subprocess.run(
        ["snarkjs", "groth16", "prove", "circuit_final.zkey", WITNESS_FILE, PROOF_FILE, PUBLIC_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("证明生成失败:")
        print(result.stderr)
        exit(1)
    print("证明生成成功")


def verify_proof():
    """验证证明"""
    print("验证证明...")
    result = subprocess.run(
        ["snarkjs", "groth16", "verify", VK_FILE, PUBLIC_FILE, PROOF_FILE],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("证明验证失败:")
        print(result.stderr)
        return False

    print("证明验证成功")
    return True


def export_solidity_verifier():
    """导出Solidity验证合约"""
    print("导出Solidity验证合约...")
    result = subprocess.run(
        ["snarkjs", "zkey", "export", "solidityverifier", "circuit_final.zkey", "Verifier.sol"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Solidity验证合约导出失败:")
        print(result.stderr)
        exit(1)
    print("Solidity验证合约导出成功")


def main():
    # 清理之前的文件
    clean_up()

    # 编译电路
    compile_circuit()

    # 生成输入数据
    secret_inputs, hash_value = generate_input()
    print(f"隐私输入: {secret_inputs}")
    print(f"计算得到的哈希值: {hash_value}")

    # 生成见证
    generate_witness()

    # 检查是否有ptau文件，如果没有则下载
    if not os.path.exists("pot12_final.ptau"):
        print("下载ptau文件...")
        subprocess.run(
            ["wget", "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau", "-O",
             "pot12_final.ptau"],
            check=True
        )

    # 执行可信设置
    setup_trusted_setup()

    # 生成证明
    generate_proof()

    # 验证证明
    if verify_proof():
        # 导出Solidity验证合约
        export_solidity_verifier()
        print("所有操作完成成功")


if __name__ == "__main__":
    main()
