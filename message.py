#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
与 index.html 里"发报 / 收报"完全一致的协议实现，仅用于交叉验证。

报文格式:  EN1/<密钥表行号>/<密钥块>/<正文>

  密钥块 = Enigma(日报密钥, 起始=G).encrypt(M)        # M 是本报随机的消息密钥
  正文   = Enigma(日报密钥, 起始=M).encrypt(校验组 + 明文)

日报密钥（转子序 / 环位 / 插线板）和基准位置 G 来自密钥本，必须另行安全送达；
报文里只有行号、被加密过的 M、以及用 M 加密的正文。
"""
import random
import string
import sys

sys.path.insert(0, "enigma-demo")

from enigma import Enigma  # noqa: E402


def check_group(text):
    """3 字母校验组；与网页版 checkGroup 逐位相同。"""
    a, b, c = 7, 11, 13
    s = "".join(ch for ch in text.upper() if ch.isalpha())
    for i, ch in enumerate(s):
        v = ord(ch) - 65
        a = (a * 31 + v) % 26
        b = (b * 17 + v + i) % 26
        c = (c * 7 + v * (i + 1) + 5) % 26
    return chr(a + 65) + chr(b + 65) + chr(c + 65)


def send(plaintext, daily, base, keyid, message_key=None):
    rotors, reflector, rings, plugs = daily
    m = message_key or "".join(random.choice(string.ascii_uppercase) for _ in range(3))
    key_block = Enigma(rotors, reflector, rings, base, plugs).encrypt(m)
    body = check_group(plaintext) + "".join(ch for ch in plaintext.upper() if ch.isalpha())
    cipher = Enigma(rotors, reflector, rings, m, plugs).encrypt(body)
    return f"EN1/{keyid}/{key_block}/{cipher}", m, key_block


def receive(wire, daily, base):
    rotors, reflector, rings, plugs = daily
    _tag, keyid, key_block, cipher = wire.split("/")
    m = Enigma(rotors, reflector, rings, base, plugs).encrypt(key_block)
    plain = Enigma(rotors, reflector, rings, m, plugs).encrypt(cipher)
    check, body = plain[:3], plain[3:]
    return keyid, m, check, body, check == check_group(body)


if __name__ == "__main__":
    daily = (("I", "II", "III"), "B", "AAA", ())
    plaintext = "WETTERVORHERSAGEFUERMORGEN"
    wire, m, key_block = send(plaintext, daily, "AAA", "D314", message_key="QWE")
    print("明文        :", plaintext)
    print("消息密钥 M  :", m, "（密钥块", key_block, "）")
    print("报文        :", wire)
    _keyid, mm, check, body, ok = receive(wire, daily, "AAA")
    print("收报自解    :", body, "｜校验组", check, "→", "通过" if ok else "失败")
