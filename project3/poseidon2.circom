// Poseidon2哈希算法的Circom电路实现
// 参数: (n,t,d) = (256,3,5)
// 256位输出，状态大小为3，S盒指数为5

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// 定义有限域 - BN254曲线的 scalar field
constant MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

// Poseidon2 (256,3,5) 参数 - 来自参考文档Table1
constant R_F = 8;    // 完全轮数
constant R_P = 4;    // 部分轮数
constant T = 3;      // 状态大小

// 轮常量 (简化版，实际应用中需要使用完整常量)
constant ROUND_CONSTANTS = [
    // 完全轮 0
    [1, 2, 3],
    // 完全轮 1
    [4, 5, 6],
    // 完全轮 2
    [7, 8, 9],
    // 完全轮 3
    [10, 11, 12],
    // 完全轮 4
    [13, 14, 15],
    // 完全轮 5
    [16, 17, 18],
    // 完全轮 6
    [19, 20, 21],
    // 完全轮 7
    [22, 23, 24],
    // 部分轮 0
    [25, 0, 0],
    // 部分轮 1
    [26, 0, 0],
    // 部分轮 2
    [27, 0, 0],
    // 部分轮 3
    [28, 0, 0],
    // 完全轮 8
    [29, 30, 31],
    [32, 33, 34],
    [35, 36, 37],
    [38, 39, 40],
    [41, 42, 43],
    [44, 45, 46],
    [47, 48, 49],
    [50, 51, 52]
];

// 混合矩阵 (简化版)
constant MIX_MATRIX = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
];

// 模加法
template AddMod() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== (a + b) % MOD;
}

// 模乘法
template MulMod() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== (a * b) % MOD;
}

// 模幂运算 - 计算 a^e mod MOD
template PowMod(e) {
    signal input a;
    signal output out;
    
    if (e == 0) {
        out <== 1;
    } else if (e == 1) {
        out <== a;
    } else {
        signal t;
        component mul = MulMod();
        mul.a <== a;
        mul.b <== a;
        t <== mul.out;
        
        for (var i = 2; i < e; i++) {
            component mul_i = MulMod();
            mul_i.a <== t;
            mul_i.b <== a;
            t <== mul_i.out;
        }
        
        out <== t;
    }
}

// S盒 - x^5 mod MOD
template SBox() {
    signal input in;
    signal output out;
    
    component p1 = MulMod();
    p1.a <== in;
    p1.b <== in;
    
    component p2 = MulMod();
    p2.a <== p1.out;
    p2.b <== in;
    
    component p3 = MulMod();
    p3.a <== p2.out;
    p3.b <== in;
    
    component p4 = MulMod();
    p4.a <== p3.out;
    p4.b <== in;
    
    out <== p4.out;
}

// 加法轮常量
template AddRoundConstants(round) {
    signal input state[T];
    signal output out[T];
    
    for (var i = 0; i < T; i++) {
        component add = AddMod();
        add.a <== state[i];
        add.b <== ROUND_CONSTANTS[round][i];
        out[i] <== add.out;
    }
}

// 混合层
template MixLayer() {
    signal input state[T];
    signal output out[T];
    
    for (var i = 0; i < T; i++) {
        signal sum;
        sum <== 0;
        
        for (var j = 0; j < T; j++) {
            component mul = MulMod();
            mul.a <== state[j];
            mul.b <== MIX_MATRIX[i][j];
            
            component add = AddMod();
            add.a <== sum;
            add.b <== mul.out;
            
            sum <== add.out;
        }
        
        out[i] <== sum;
    }
}

// 完全轮
template FullRound(round) {
    signal input state[T];
    signal output out[T];
    
    // 1. 加法轮常量
    signal after_add[T];
    component arc = AddRoundConstants(round);
    for (var i = 0; i < T; i++) {
        arc.state[i] <== state[i];
        after_add[i] <== arc.out[i];
    }
    
    // 2. 子词替换 (S盒)
    signal after_sbox[T];
    for (var i = 0; i < T; i++) {
        component sbox = SBox();
        sbox.in <== after_add[i];
        after_sbox[i] <== sbox.out;
    }
    
    // 3. 混合层
    component mix = MixLayer();
    for (var i = 0; i < T; i++) {
        mix.state[i] <== after_sbox[i];
        out[i] <== mix.out[i];
    }
}

// 部分轮
template PartialRound(round) {
    signal input state[T];
    signal output out[T];
    
    // 1. 加法轮常量
    signal after_add[T];
    component arc = AddRoundConstants(round);
    for (var i = 0; i < T; i++) {
        arc.state[i] <== state[i];
        after_add[i] <== arc.out[i];
    }
    
    // 2. 子词替换 (仅对第一个元素应用S盒)
    signal after_sbox[T];
    component sbox = SBox();
    sbox.in <== after_add[0];
    after_sbox[0] <== sbox.out;
    
    for (var i = 1; i < T; i++) {
        after_sbox[i] <== after_add[i];
    }
    
    // 3. 混合层
    component mix = MixLayer();
    for (var i = 0; i < T; i++) {
        mix.state[i] <== after_sbox[i];
        out[i] <== mix.out[i];
    }
}

// Poseidon2哈希函数
template Poseidon2Hash() {
    // 隐私输入: 哈希原象 (一个block)
    signal private input input[2];  // 对于t=3，输入为2个元素，第三个元素为1
    
    // 公开输出: 哈希结果
    signal output hash;
    
    // 初始化状态
    signal state[T];
    state[0] <== input[0];
    state[1] <== input[1];
    state[2] <== 1;  // 领域分隔符
    
    // 前半部分完全轮
    for (var r = 0; r < R_F/2; r++) {
        signal new_state[T];
        component fr = FullRound(r);
        for (var i = 0; i < T; i++) {
            fr.state[i] <== state[i];
            new_state[i] <== fr.out[i];
        }
        state <== new_state;
    }
    
    // 部分轮
    for (var r = 0; r < R_P; r++) {
        signal new_state[T];
        component pr = PartialRound(R_F/2 + r);
        for (var i = 0; i < T; i++) {
            pr.state[i] <== state[i];
            new_state[i] <== pr.out[i];
        }
        state <== new_state;
    }
    
    // 后半部分完全轮
    for (var r = 0; r < R_F/2; r++) {
        signal new_state[T];
        component fr = FullRound(R_F/2 + R_P + r);
        for (var i = 0; i < T; i++) {
            fr.state[i] <== state[i];
            new_state[i] <== fr.out[i];
        }
        state <== new_state;
    }
    
    // 输出哈希结果 (取状态的第一个元素)
    hash <== state[0];
}

// 主电路: 验证哈希值是否正确
template Main() {
    // 公开输入: 预期的哈希值
    signal public input expectedHash;
    
    // 使用Poseidon2哈希函数
    component poseidon = Poseidon2Hash();
    
    // 约束: 计算出的哈希值必须等于预期的哈希值
    poseidon.hash === expectedHash;
}

// 实例化主电路
component main = Main();
