#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
double-step 的可视化：把转子摆到 A D U，然后连按四次键，
观察中转子（II，缺口 E）连续前进两步。

预期轨迹：ADU→ADV  ADV→AEW  AEW→BFX  BFX→BFY
         第一转：右转子到缺口 V
         第二转：中转子被带动 D→E，右转子 V→W
         第三转：中转子自己正处在缺口 E，于是中、左转子一起走 E→F、A→B
                 —— 这就是 double step，中间转子连着走了两步
"""
import sys

sys.path.insert(0, "enigma-demo")

from enigma import Enigma  # noqa: E402


def windows(machine):
    return "".join(chr(r.position + 65) for r in reversed(machine.rotors))


machine = Enigma(("I", "II", "III"), "B", "AAA", "ADU")
print(f"起始窗口 {windows(machine)}")
for press in range(1, 5):
    before = windows(machine)
    out = machine.encrypt_char("A")
    print(f"  第{press}次按键(A→{out})  {before} → {windows(machine)}")
