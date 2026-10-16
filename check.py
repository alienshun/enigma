#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位约定问题：转子序方向 × 环位偏移符号，看哪个给出标准向量 BDZGO。"""

ROTORS = {
    "I":   ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":  ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III": ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
}
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
A = ord("A")


def scramble(rotors, x, sign):
    """rotors: 从右到左排列的 (wiring, notch, ring, pos)"""
    for wiring, _, ring, pos in rotors:
        off = (pos - ring) % 26 if sign > 0 else (ring - pos) % 26
        x = (wiring[(x + off) % 26] - off) % 26
    x = ord(REFLECTOR_B[x]) - A
    for wiring, _, ring, pos in reversed(rotors):
        inv = [0] * 26
        for i, v in enumerate(wiring):
            inv[v] = i
        off = (pos - ring) % 26 if sign > 0 else (ring - pos) % 26
        x = (inv[(x + off) % 26] - off) % 26
    return x


def run(order, sign):
    """order 是从左到右的转子名（如 I II III）"""
    rtl = list(reversed(order))                 # 转成从右到左
    rotors = []
    for name in rtl:
        wiring = [ord(c) - A for c in ROTORS[name][0]]
        notch = ord(ROTORS[name][1]) - A
        rotors.append((wiring, notch, 0, 0))     # 环位 AAA，起始 AAA
    out = []
    positions = [0, 0, 0]                        # 右中左
    for _ in range(5):
        right, middle, left = positions
        if middle == rotors[1][1]:
            middle = (middle + 1) % 26
            left = (left + 1) % 26
        elif right == rotors[0][1]:
            middle = (middle + 1) % 26
        right = (right + 1) % 26
        positions = [right, middle, left]
        state = []
        for (wiring, notch, _, _), pos in zip(rotors, positions):
            state.append((wiring, notch, 0, pos))
        out.append(chr(scramble(state, 0, sign) + A))   # 明文 A
    return "".join(out)


print("目标向量: AAAAA -> BDZGO")
for order in (("I", "II", "III"), ("III", "II", "I")):
    for sign in (1, -1):
        label = " ".join(order)
        print(f"  转子(左→右) {label:<12} 偏移 sign={sign:+d}  ->  {run(order, sign)}")
