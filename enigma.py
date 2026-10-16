#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enigma I (Wehrmacht) 模拟器：3 转子 + 插线板 + 反射器。

步进是真实的爪式机构，不是"三转子同步进位"：

    中间转子在缺口位   -> 中间、左转子一起走，然后右转子走   (double step)
    否则右转子在缺口位 -> 中间转子走，然后右转子走
    否则               -> 右转子走

所以转子周期是 26*25*26 = 16900，而不是 26^3 = 17576。
这个不规则的 double step 恰恰是最早被利用的结构性弱点之一。
"""

A_CODE = ord("A")

ROTORS = {
    # 名称: (布线, 缺口字母；VI–VIII 有两个缺口 M 和 Z)
    # 数据来源：Tony Sale（布莱切利园博物馆原馆长）的转子规格页
    # https://www.codesandciphers.org.uk/enigma/rotorspec.htm
    "I":    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":   ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III":  ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":   ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":    ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    "VI":   ("JPGVOUMFYQBENHZRDKASXLICTW", "MZ"),
    "VII":  ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "MZ"),
    "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "MZ"),
    # 薄转子（M4 专用）：只能装在第四个位置，没有缺口，加密过程中永不步进
    "Beta":  ("LEYJVCNIXWPBQMDRTAKZGFUHOS", ""),
    "Gamma": ("FSOKANUERHMBTIYCWLQPZXVGJD", ""),
}

REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
    # 薄反射器（M4 专用）
    "B-Thin": "ENKQAUYWJICOPBLMDXZVFTHRGS",
    "C-Thin": "RDOBJNTKVEHMLFCWZAXGYIPSUQ",
}


class Rotor:
    def __init__(self, name, ring=0, position=0):
        wiring, notch_letters = ROTORS[name]
        self.name = name
        self.forward = [ord(c) - A_CODE for c in wiring]
        self.backward = [0] * 26
        for index, value in enumerate(self.forward):
            self.backward[value] = index
        # 缺口可能不止一个（VI–VIII 是 M 和 Z），薄转子则一个都没有
        self.notches = {ord(c) - A_CODE for c in notch_letters}
        self.ring = ring
        self.position = position

    @property
    def offset(self):
        return (self.position - self.ring) % 26

    def advance(self):
        self.position = (self.position + 1) % 26

    def at_notch(self):
        return self.position in self.notches

    def encode_forward(self, x):
        offset = self.offset
        return (self.forward[(x + offset) % 26] - offset) % 26

    def encode_backward(self, x):
        offset = self.offset
        return (self.backward[(x + offset) % 26] - offset) % 26


class Enigma:
    def __init__(self, rotors=("I", "II", "III"), reflector="B",
                 rings="AAA", positions="AAA", plugboard=(),
                 reflector_override=None):
        self.rotor_names = tuple(rotors)
        self.reflector_name = reflector
        self.rings = rings
        # 约定：rotors / rings / positions 一律按"左→右"给出（与历史文件记载一致），
        # 内部按"右→左"存放，因为步进与信号都是从右转子开始的。
        # 四转子（M4）时最左边那个是薄转子 Beta/Gamma，它永不步进。
        # （之前直接把第一个名字当成右转子，导致标准向量 AAAAA 得 FTZMG 而非 BDZGO。）
        left_to_right = list(zip(rotors, rings, positions))
        self.rotors = [Rotor(name, ord(r) - A_CODE, ord(p) - A_CODE)
                       for name, r, p in reversed(left_to_right)]
        self.reflector = (list(reflector_override) if reflector_override is not None
                          else [ord(c) - A_CODE for c in REFLECTORS[reflector]])
        self.plug = list(range(26))
        for left, right in plugboard:
            x, y = ord(left) - A_CODE, ord(right) - A_CODE
            self.plug[x], self.plug[y] = y, x

    @property
    def is_four_rotor(self):
        return len(self.rotors) == 4

    def step(self):
        # 只有最右边三个转子参与步进；最左边的薄转子（若有）保持原地不动
        right, middle, left = self.rotors[0], self.rotors[1], self.rotors[2]
        if middle.at_notch():
            middle.advance()
            left.advance()
        elif right.at_notch():
            middle.advance()
        right.advance()

    def scramble(self, x):
        """转子 + 反射器，不含插线板。这个变换是对合的。"""
        for rotor in self.rotors:
            x = rotor.encode_forward(x)
        x = self.reflector[x]
        for rotor in reversed(self.rotors):
            x = rotor.encode_backward(x)
        return x

    def encrypt_char(self, ch):
        self.step()
        x = self.plug[ord(ch.upper()) - A_CODE]
        x = self.scramble(x)
        return chr(self.plug[x] + A_CODE)

    def encrypt(self, text):
        return "".join(self.encrypt_char(c) for c in text if c.isalpha())


def folded_reflector(thin_name, thin_ring, thin_position, reflector_name):
    """
    把薄转子折进反射器（M4 的关键结构事实）。

    薄转子加密过程中永不转动，所以对某一天而言

        薄转子 ∘ 薄反射器 ∘ 薄转子⁻¹

    就是一个固定的、新的反射器。于是 **M4 在结构上等价于一台换了反射器的三转子机**，
    26 个薄转子位置给出 26 个不同的等效反射器 —— 四转子炸弹机就是按这个思路做的：
    外层轮 26 次薄转子位置，内层跑现成的三转子搜索。
    """
    thin = Rotor(thin_name, ord(thin_ring) - A_CODE, ord(thin_position) - A_CODE)
    base = [ord(c) - A_CODE for c in REFLECTORS[reflector_name]]
    return [thin.encode_backward(base[thin.encode_forward(x)]) for x in range(26)]


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest():
    ok = True

    def check(name, passed, detail=""):
        nonlocal ok
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name:<34} {detail}")

    # 1) 公开测试向量：I II III / B / 环位 AAA / 起始 AAA / 无插线板
    machine = Enigma(("I", "II", "III"), "B", "AAA", "AAA")
    got = machine.encrypt("AAAAA")
    check("标准向量 AAAAA", got == "BDZGO", f"得到 {got}，期望 BDZGO")

    # 2) 对合性：同起始位置下再加密一次应还原
    plain = "WETTERVORHERSAGE"
    cipher = Enigma(("IV", "II", "V"), "C", "KLM", "QWE",
                    ("AB", "CD", "EF")).encrypt(plain)
    back = Enigma(("IV", "II", "V"), "C", "KLM", "QWE",
                  ("AB", "CD", "EF")).encrypt(cipher)
    check("对合性 E(E(x))=x", back == plain, f"{back}")

    # 3) 没有字母能加密成自己
    worst = None
    for positions in ("AAA", "QRS", "XYZ", "KDO", "ZZZ"):
        for ring in ("AAA", "BCD"):
            m = Enigma(("I", "II", "III"), "B", ring, positions)
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if m.encrypt_char(letter) == letter:
                    worst = (positions, ring, letter)
    check("无不动点（不加密成自己）", worst is None, f"{worst or '全部 26 字母 × 10 组设置'}")

    # 4) double-stepping 的指纹：转子周期 = 26*25*26
    m = Enigma(("I", "II", "III"), "B", "AAA", "AAA")
    steps = 0
    while True:
        m.step()
        steps += 1
        if tuple(r.position for r in m.rotors) == (0, 0, 0):
            break
        if steps > 100000:
            break
    check("转子周期（double step）", steps == 16900, f"{steps} 步回到 AAA（26^3=17576）")

    # 5) 双缺口转子：VI–VIII 的换档点在 A 和 N，即缺口 M 和 Z
    notch_ok = True
    for name in ("VI", "VII", "VIII"):
        r = Rotor(name)
        if r.notches != {ord("M") - A_CODE, ord("Z") - A_CODE}:
            notch_ok = False
    for name in ("I", "II", "III", "IV", "V"):
        if len(Rotor(name).notches) != 1:
            notch_ok = False
    check("VI–VIII 双缺口 M/Z", notch_ok, "I–V 单缺口，VI–VIII 两个")

    # 6) M4 的薄转子永不步进
    m4 = Enigma(("Beta", "V", "VI", "VIII"), "B-Thin", "AAAA", "AAAA")
    thin_start = m4.rotors[3].position
    m4.encrypt("WETTERVORHERSAGEFUERMORGEN")
    check("薄转子永不步进", m4.rotors[3].position == thin_start,
          f"跑完 26 个字母后仍在 {chr(thin_start + A_CODE)} 位")

    # 7) M4 的转子周期仍是 16900（薄转子不动，周期由三个动转子决定）
    #    注意必须用单缺口转子：16900 这个数只在单缺口时成立。
    m4b = Enigma(("Beta", "IV", "II", "V"), "B-Thin", "AAAA", "AAAA")
    steps = 0
    while True:
        m4b.step()
        steps += 1
        if tuple(r.position for r in m4b.rotors) == (0, 0, 0, 0):
            break
        if steps > 100000:
            break
    check("M4 转子周期（单缺口）", steps == 16900, f"{steps} 步回到 AAAA")

    # 8) 双缺口会破坏"步进是一个置换"：缺口不止一个时，从 AAAA 出发的轨道
    #    不再回到 AAAA（单缺口时周期恰好 16900）。这是 VI–VIII 的真实后果。
    m4c = Enigma(("Beta", "V", "VI", "VIII"), "B-Thin", "AAAA", "AAAA")
    seen = set()
    returned = False
    for _ in range(30000):
        m4c.step()
        state = tuple(r.position for r in m4c.rotors)
        if state == (0, 0, 0, 0):
            returned = True
            break
        if state in seen:
            break
        seen.add(state)
    check("双缺口使步进不再是置换", not returned,
          f"轨道长度 {len(seen)}，不回起点（单缺口时为 16900）")

    # 9) 最关键的一条：M3 兼容模式不变量
    #    官方说明——把薄转子 β 拨到 A 位、配薄反射器 b，M4 就等同于一台 M3。
    #    这一条同时钉住了两批独立公布的常量（Tony Sale 的布线表 + Crypto Museum 的用法说明）。
    folded = folded_reflector("Beta", "A", "A", "B-Thin")
    normal_b = [ord(c) - A_CODE for c in REFLECTORS["B"]]
    check("β@A + 薄反射器 b ≡ 普通 UKW B", folded == normal_b,
          "折叠后的等效反射器与 UKW B 逐位相同" if folded == normal_b else "不一致")

    # 10) 四转子在兼容模式下必须跑出三转子的结果
    text = "WETTERVORHERSAGEFUERMORGEN"
    four = Enigma(("Beta", "IV", "II", "V"), "B-Thin", "AAAA", "AAAA")
    three = Enigma(("IV", "II", "V"), "B", "AAA", "AAA")
    four_out, three_out = four.encrypt(text), three.encrypt(text)
    check("四转子跑出三转子结果", four_out == three_out, f"{four_out[:16]}…")

    print(f"  自检总结: {'全部通过' if ok else '存在失败'}")
    return ok


if __name__ == "__main__":
    print("Enigma I 自检")
    selftest()
