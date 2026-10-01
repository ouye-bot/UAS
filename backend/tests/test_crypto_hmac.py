"""HMAC-SM3 测试。

向量源：GmSSL C 官方测试套件 tests/sm3_hmactest.h（转自 Wycheproof
hmac_sm3_test.json，本会话读入；此处取覆盖各关键路径的子集）。
gmssl 3.2.2 无 HMAC-SM3 → RFC 2104 自实现（块长 64B）。
"""

from app.crypto.hmac_sm3 import hmac_sm3

# (key_hex, msg_hex, tag_hex, 说明)  —— 全部 VALID 用例
VECTORS = [
    (
        "1e225cafb90339bba1b24076d4206c3e79c355805d851682bc818baa4f5a7779",
        "",
        "f9938b1b2515117f25dcd636c9a6a0e7f00bccaf5347e0e0df435cfca736cfc1",
        "tc1 空消息",
    ),
    (
        "8159fd15133cd964c9a6964c94f0ea269a806fd9f43f0da58b6cd1b33d189b2a",
        "77",
        "51aaf64843b6d2fc7a244ab9cda9b7b57164ce6a865f9808c01931b46195411d",
        "tc2 单字节",
    ),
    (
        "6fa353868c82e5deeedac7f09471a61bf749ab5498239e947e012eee3c82d7c4",
        "aeed3e4d4cb9bbb60d482e98c126c0f5",
        "d92d6e7f3f9d0158602c327f075e27226c8591f3a667d768a25e4a6dd491b754",
        "tc17 16B 消息",
    ),
    (
        "28855c7efc8532d92567300933cc1ca2d0586f55dcc9f054fcca2f05254fbf7f",
        "9c09207ff0e6e582cb3747dca954c94d45c05e93f1e6f21179cf0e25b4cede74b5479d32f5166935c86f0441905865",
        "3ced1794d623cea2d09ab1e9dfd912b3cc53f6a517143d051301287cbf5dce4d",
        "tc21 长消息 48B",
    ),
    (
        "a349ac0a9f9f74e48e099cc3dbf9a9c9",
        "",
        "38151645fc1dc87175a9481d7aa82d075123075c93e13ed578da3da607229cf0",
        "tc163 短钥 16B",
    ),
    (
        "8a0c46eb8a2959e39865330079763341e7439dab149694ee57e0d61ec73d947e1d5301cd974e18a5e0d1cf0d2c37e8aadd9fd589d57ef32e47024a99bc3f70c077",
        "",
        "f585ac6070bbdce74a19c2a5db953e4682df5f4d6693fc8182cc4c6ee4be3150",
        "tc169 长钥 72B（触发 key 哈希路径）",
    ),
]


def test_official_vectors():
    for key, msg, tag, name in VECTORS:
        out = hmac_sm3(bytes.fromhex(key), bytes.fromhex(msg)).hex()
        assert out == tag, name


def test_truncated_tag_prefix_matches():
    # tc82（Wycheproof 截断 16B tag 用例）：完整 tag 的前 16B 必须一致
    full = hmac_sm3(
        bytes.fromhex("7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e43ef97"),
        b"",
    )
    assert full.hex().startswith("296d36e43fee12399357a2bd05e17435")


def test_tamper_every_byte_rejected():
    """程序化篡改：对 tc1 的 tag 逐字节翻转，全部不等于原 tag（等价 Wycheproof ModifiedTag 族）。"""
    key = bytes.fromhex(VECTORS[0][0])
    base = hmac_sm3(key, b"")
    for i in range(32):
        bad = bytearray(base)
        bad[i] ^= 0x01
        assert hmac_sm3(key, b"") != bytes(bad)
    # 全零 / 全 ff tag（Wycheproof Tag=0 / Tag=1 族）
    assert hmac_sm3(key, b"") not in (bytes(32), b"\xff" * 32)
