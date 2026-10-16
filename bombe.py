#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Turing-Welchman 炸弹机（Bombe）的软件复刻：已知明文（crib）攻击。

原理
----
整机变换 E = P · S · P，其中 P 是插线板（对合），S 是转子+反射器（对合）。
对 crib 的第 i 个字符：E_i(p_i) = c_i。记 x = P(p_i)，则

    S_i(x) = P(c_i)

于是"知道一个字母的插线伙伴"就能沿菜单（menu）把伙伴关系推下去；
又因为 P 是对合的（P(P(a)) = a，即 Welchman 的"对角板"），
约束可以双向传播：partner[c_i] = S_i(partner[p_i])，反之亦然。
矛盾的假设（某字母插到自己、或与已有分配冲突）立刻死掉。

搜索空间：转子序 × 17576 个起始位置 × 26 个假设。
历史上一台 Bombe 一次只接一种转子序，这里保持一致。
"""

import itertools
import time

from enigma import A_CODE, REFLECTORS, ROTORS, Enigma, folded_reflector


class RotorBank:
    """只跟踪转子位置的高速步进器，用于搜索内环。"""

    def __init__(self, rotor_names, rings):
        # 与 Enigma 一致：入参按"左→右"，内部按"右→左"
        names = list(reversed(rotor_names))
        ring_values = list(reversed(rings))
        # 缺口可能不止一个（VI–VIII 是 M 和 Z），所以存成集合
        self.notches = [{ord(c) - A_CODE for c in ROTORS[n][1]} for n in names]
        self.rings = [ord(r) - A_CODE for r in ring_values]
        self.wiring = [[ord(c) - A_CODE for c in ROTORS[n][0]] for n in names]
        self.inverse = []
        for wiring in self.wiring:
            back = [0] * 26
            for index, value in enumerate(wiring):
                back[value] = index
            self.inverse.append(back)

    def advance(self, position):
        right, middle, left = position
        if middle in self.notches[1]:
            middle = (middle + 1) % 26
            left = (left + 1) % 26
        elif right in self.notches[0]:
            middle = (middle + 1) % 26
        right = (right + 1) % 26
        return (right, middle, left)

    def offsets(self, position):
        return tuple((p - r) % 26 for p, r in zip(position, self.rings))

    def scramble(self, offsets, reflector, x):
        for offset, wiring in zip(offsets, self.wiring):
            x = (wiring[(x + offset) % 26] - offset) % 26
        x = reflector[x]
        for offset, inverse in zip(reversed(offsets), reversed(self.inverse)):
            x = (inverse[(x + offset) % 26] - offset) % 26
        return x


def crib_offsets(plaintext, ciphertext, crib):
    """
    克里布拖动：先做最便宜的必要条件筛选 —— Enigma 不会把字母加密成它自己，
    所以任何让 crib 某位与密文相同的起始偏移都不可能。
    """
    survivors = []
    for offset in range(len(ciphertext) - len(crib) + 1):
        window = ciphertext[offset:offset + len(crib)]
        if all(p != c for p, c in zip(crib, window)):
            survivors.append(offset)
    return survivors


def search_core(core_names, core_rings, reflector_ints, pairs, offset):
    """
    在**已经折好反射器**的三转子上跑一遍炸弹机搜索。

    返回 [(start3, partner)]；start3 是内部（右→左）顺序的三元组。
    """
    bank = RotorBank(core_names, core_rings)

    menu = {}
    for index, (p, c) in enumerate(pairs):
        menu.setdefault(p, []).append((index, c))
        menu.setdefault(c, []).append((index, p))

    # 假设的落点选在度数最高的字母上（历史上的"输入字母"）
    input_letter = max(menu, key=lambda letter: len(menu[letter]))

    stops = []
    for start in itertools.product(range(26), repeat=3):
        state = start
        for _ in range(offset + 1):        # 每个字符先步进再加密
            state = bank.advance(state)
        offsets_at = []
        for _ in pairs:
            offsets_at.append(bank.offsets(state))
            state = bank.advance(state)

        cache = {}

        def scrambler(index, x, offsets_at=offsets_at, cache=cache,
                      bank=bank, reflector=reflector_ints):
            key = (index, x)
            value = cache.get(key)
            if value is None:
                value = bank.scramble(offsets_at[index], reflector, x)
                cache[key] = value
            return value

        for guess in range(26):
            # guess == input_letter 也必须试：那表示 input_letter 根本没插线，
            # 这是一个合法的插线板状态（不动点），不是矛盾。
            partner = [-1] * 26
            partner[input_letter] = guess
            partner[guess] = input_letter
            stack = [input_letter, guess]
            dead = False
            while stack and not dead:
                letter = stack.pop()
                known = partner[letter]
                for index, other in menu.get(letter, ()):
                    implied = scrambler(index, known)
                    current = partner[other]
                    if current == -1:
                        # implied == other 是"other 未插线"（不动点），合法
                        if partner[implied] not in (-1, other):
                            dead = True
                            break
                        partner[other] = implied
                        partner[implied] = other
                        stack.append(other)
                        if implied != other:
                            stack.append(implied)
                    elif current != implied:
                        dead = True
                        break
            if not dead:
                stops.append((start, partner))
    return stops


def bombe(rotor_names, reflector_name, rings, ciphertext, crib, offset,
          verbose=False):
    """
    返回 (stops, 秒数)。

      三转子：stop = (start3, partner)
      四转子（M4）：stop = ((薄转子位置,) + start3, partner)

    四转子用的是"反射器折叠"：薄转子加密过程中不动，于是它可以和薄反射器
    复合成一个新的等效反射器，M4 直接退化成一串三转子问题——
    外层轮 26 个薄转子位置，内层跑现成的三转子搜索。这就是四转子炸弹机的思路。
    """
    pairs = [(ord(p) - A_CODE, ord(c) - A_CODE)
             for p, c in zip(crib, ciphertext[offset:offset + len(crib)])]
    started = time.time()
    stops = []

    if len(rotor_names) == 4:
        thin_name, thin_ring = rotor_names[0], rings[0]
        core_names, core_rings = tuple(rotor_names[1:]), rings[1:]
        for thin_position in range(26):
            folded = folded_reflector(thin_name, thin_ring,
                                      chr(thin_position + A_CODE), reflector_name)
            for start3, partner in search_core(core_names, core_rings, folded,
                                               pairs, offset):
                stops.append(((thin_position,) + start3, partner))
    else:
        reflector_ints = [ord(c) - A_CODE for c in REFLECTORS[reflector_name]]
        for start3, partner in search_core(tuple(rotor_names), rings,
                                           reflector_ints, pairs, offset):
            stops.append((start3, partner))

    elapsed = time.time() - started
    if verbose:
        print(f"    转子序 {' '.join(rotor_names)} 反射器 {reflector_name}: "
              f"{len(stops)} 个 stop, {elapsed:.1f}s")
    return stops, elapsed


def plugboard_from_partner(partner):
    pairs = []
    for i in range(26):
        j = partner[i]
        if j > i:
            pairs.append((chr(i + A_CODE), chr(j + A_CODE)))
    return pairs


def verify(stop, rotor_names, reflector_name, rings, ciphertext, crib, offset):
    """用 stop 给出的插线板解整条密文，看 crib 是否复现。"""
    start, partner = stop
    if len(rotor_names) == 4:
        # start = (薄转子位置, 右, 中, 左)
        thin_position, core = start[0], start[1:]
        positions = (chr(thin_position + A_CODE)
                     + "".join(chr(p + A_CODE) for p in reversed(core)))
    else:
        positions = "".join(chr(p + A_CODE) for p in reversed(start))
    machine = Enigma(rotor_names, reflector_name, rings, positions,
                     plugboard_from_partner(partner))
    plain = machine.encrypt(ciphertext)
    return positions, plain[offset:offset + len(crib)] == crib, plain


def m4_demo(plaintext, crib):
    """M4 四转子演示：薄转子不动 → 折叠进反射器 → 外层轮 26 个位置。"""
    rotors4 = ("Beta", "V", "VI", "VIII")
    rings4 = "AAAA"
    true_positions4 = "MQWE"          # 薄转子 Beta 在 M 位；核心（左→右）Q W E
    plugboard4 = (("AM", "FI", "NV", "PS", "TU", "WZ"))
    cipher4 = Enigma(rotors4, "B-Thin", rings4, true_positions4,
                     plugboard4).encrypt(plaintext)
    offset = plaintext.index(crib)
    hypotheses = 26 * 17576 * 26

    print("\n== M4 四转子演示（薄转子 + 反射器折叠）==")
    print(f"  转子序 {' '.join(rotors4)} / 反射器 B-Thin / 环位 {rings4}")
    print(f"  真实密钥: 薄转子 Beta 在 {true_positions4[0]} 位，"
          f"核心起始 {true_positions4[1:]}，插线 {list(plugboard4)}")
    print(f"  密文: {cipher4}")

    stops, elapsed = bombe(rotors4, "B-Thin", rings4, cipher4, crib, offset)
    hits = []
    for stop in stops:
        positions, matched, plain = verify(stop, rotors4, "B-Thin", rings4,
                                           cipher4, crib, offset)
        if matched:
            hits.append((positions, stop[1], plain))

    print(f"  搜索量 {hypotheses:,} 个假设"
          f"（26 个薄转子位置 × 17576 个三转子起始 × 26 个插线假设）")
    print(f"  {len(stops)} 个 stop，验证通过 {len(hits)} 个，用时 {elapsed:.1f}s")
    for positions, partner, plain in hits:
        recovered = plugboard_from_partner(partner)
        print(f"  → 命中！完整起始位置 {positions}（薄转子 {positions[0]}）")
        print(f"     恢复插线 {recovered}")
        print(f"     密钥完全正确: "
              f"{positions == true_positions4 and set(map(frozenset, recovered)) == set(map(frozenset, plugboard4))}")
        print(f"     破译全文: {plain}")
    print("  对照：同一段 crib，三转子只要 17576 × 26 = 456,976 个假设，"
          "M4 正好是它的 26 倍。")
    print("  当年布莱切利园就是被这 26 倍卡住：算力不够，只能等美国 NCR 造出")
    print("  ~120 台四转子炸弹机，加上缴获的天气短码本提供可靠 crib，才重新读通。")


if __name__ == "__main__":
    from enigma import selftest

    print("== Enigma 自检 ==")
    selftest()

    print("\n== 场景 ==")
    rotor_names = ("I", "II", "III")
    reflector_name, rings = "B", "AAA"
    plugboard = (("AM", "FI", "NV", "PS", "TU", "WZ"))
    true_positions = "QWE"
    plaintext = "VONXOBERKOMMANDOXANXALLEXXWETTERVORHERSAGEFUERMORGENXWINDXAUSXWEST"
    ciphertext = Enigma(rotor_names, reflector_name, rings, true_positions,
                        plugboard).encrypt(plaintext)
    print(f"  明文: {plaintext}")
    print(f"  密文: {ciphertext}")
    print(f"  真实密钥: 转子 {' '.join(rotor_names)} / 环位 {rings} / "
          f"起始 {true_positions} / 插线 {plugboard}")

    crib = "WETTERVORHERSAGEFUERMORGEN"
    true_offset = plaintext.index(crib)
    print(f"\n== 克里布拖动（crib «{crib}»，长度 {len(crib)}）==")
    survivors = crib_offsets(plaintext, ciphertext, crib)
    total_slots = len(plaintext) - len(crib) + 1
    print(f"  {total_slots} 个候选偏移中，通过'不加密成自己'筛选的有 {len(survivors)} 个"
          f"（真实偏移 {true_offset}）")
    print("  注意：这个筛选很弱——真对齐一定通过，随机对齐也有约 "
          f"{(25/26)**len(crib):.0%} 的概率通过，所以它只用来砍掉明显不可能的位置。")

    # 默认只跑真实偏移 + 两个假偏移；--all 跑完所有通过筛选的偏移
    import sys
    full = "--all" in sys.argv
    if full:
        trial = list(survivors)
    else:
        trial = [true_offset]
        for offset in survivors:
            if offset != true_offset and len(trial) < 3:
                trial.append(offset)

    print("\n== 炸弹机搜索（每个偏移 17576 个起始位置 × 26 个假设）==")
    total_stops = 0
    hits = []
    started = time.time()
    hypotheses_per_offset = 26 * 17576
    for offset in trial:
        stops, elapsed = bombe(rotor_names, reflector_name, rings,
                               ciphertext, crib, offset, verbose=False)
        total_stops += len(stops)
        verified = []
        for stop in stops:
            positions, matched, plain = verify(stop, rotor_names, reflector_name,
                                               rings, ciphertext, crib, offset)
            if matched:
                verified.append((positions, stop[1], plain))
                hits.append((offset, positions, stop[1], plain))
        if not full:
            tag = "真实偏移" if offset == true_offset else "假偏移"
            print(f"  [{tag} {offset}] {len(stops)} 个 stop, {elapsed:.1f}s")
            for positions, partner, plain in verified:
                recovered = plugboard_from_partner(partner)
                print(f"    → 命中！起始位置 {positions}")
                print(f"       恢复插线 {recovered}")
                print(f"       真实插线 {list(plugboard)}")
                print(f"       密钥完全正确: "
                      f"{positions == true_positions and set(map(frozenset, recovered)) == set(map(frozenset, plugboard))}")
                print(f"       破译全文: {plain}")
            if not verified:
                print(f"    → 没有 stop 能通过解密验证"
                      f"（假偏移的 stop 就是这样被淘汰的）")
        elif verified:
            print(f"  ★ 偏移 {offset}: {len(stops)} 个 stop，其中一个验证通过")

    total_time = time.time() - started
    print(f"\n  共测试 {len(trial) * hypotheses_per_offset:,} 个假设"
          f"（{len(trial)} 个偏移 × 17576 × 26），产生 {total_stops} 个 stop，"
          f"验证通过 {len(hits)} 个，用时 {total_time:.1f}s")
    for offset, positions, partner, plain in hits:
        recovered = plugboard_from_partner(partner)
        print(f"  唯一密钥: 偏移 {offset} / 起始 {positions} / 插线 {recovered}")
        print(f"  密钥完全正确: "
              f"{positions == true_positions and set(map(frozenset, recovered)) == set(map(frozenset, plugboard))}")
        print(f"  破译全文: {plain}")

    if "--m4" in sys.argv:
        m4_demo(plaintext, crib)
