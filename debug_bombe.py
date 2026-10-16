#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判决性诊断：核心关系 P(c_i) = S_i(P(p_i)) 在真密钥下是否成立。"""

import sys

sys.path.insert(0, "enigma-demo")

from bombe import RotorBank, bombe, plugboard_from_partner  # noqa: E402
from enigma import A_CODE, REFLECTORS, Enigma  # noqa: E402

rotor_names = ("I", "II", "III")
reflector_name, rings = "B", "AAA"
plug = (("AM", "FI", "NV", "PS", "TU", "WZ"))
true_positions = "QWE"
plaintext = "VONXOBERKOMMANDOXANXALLEXXWETTERVORHERSAGEFUERMORGENXWINDXAUSXWEST"
ciphertext = Enigma(rotor_names, reflector_name, rings, true_positions,
                    plug).encrypt(plaintext)
crib = "WETTERVORHERSAGEFUERMORGEN"
offset = plaintext.index(crib)
pairs = [(ord(p) - A_CODE, ord(c) - A_CODE)
         for p, c in zip(crib, ciphertext[offset:offset + len(crib)])]

P = list(range(26))
for a, b in plug:
    x, y = ord(a) - A_CODE, ord(b) - A_CODE
    P[x], P[y] = y, x

# --- 检查 1：bank.scramble 与真实机器的无插线板变换是否一致 ---
bank = RotorBank(rotor_names, rings)
machine = Enigma(rotor_names, reflector_name, rings, true_positions)
state = (ord("E") - A_CODE, ord("W") - A_CODE, ord("Q") - A_CODE)  # 右中左
for _ in range(offset + 1):
    state = bank.advance(state)
offsets_at = []
for _ in pairs:
    offsets_at.append(bank.offsets(state))
    state = bank.advance(state)

mismatch_scramble = 0
check_machine = Enigma(rotor_names, reflector_name, rings, true_positions)
for _ in range(offset + 1):
    check_machine.step()
for index in range(len(pairs)):
    # 注意：check_machine 在进入本轮时已经处于 crib 第 index 位的状态，
    # 不能再 step（上一版在这里多走了一步，导致 400 处假报警）。
    refl = [ord(c) - A_CODE for c in REFLECTORS[reflector_name]]
    for x in range(26):
        if bank.scramble(offsets_at[index], refl, x) != check_machine.scramble(x):
            mismatch_scramble += 1
    check_machine.step()
print(f"检查1  bank.scramble 与真机 scramble 不一致的 (索引,x) 对数: {mismatch_scramble}")

# --- 检查 2：核心关系 P(c_i) = S_i(P(p_i)) ---
refl = [ord(c) - A_CODE for c in REFLECTORS[reflector_name]]
bad = 0
for index, (p, c) in enumerate(pairs):
    implied = bank.scramble(offsets_at[index], refl, P[p])
    if implied != P[c]:
        bad += 1
        print(f"  菜单边 {index}: {chr(p+A_CODE)}-{chr(c+A_CODE)}  "
              f"P(p)={chr(P[p]+A_CODE)} P(c)={chr(P[c]+A_CODE)} "
              f"S(P(p))={chr(implied+A_CODE)}  不一致")
print(f"检查2  核心关系不成立的边数: {bad}/{len(pairs)}")

# --- 检查 3：菜单连通性 ---
parent = list(range(26))


def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


letters = set()
for p, c in pairs:
    letters.add(p)
    letters.add(c)
for p, c in pairs:
    a, b = find(p), find(c)
    if a != b:
        parent[a] = b
components = {}
for letter in letters:
    components.setdefault(find(letter), []).append(chr(letter + A_CODE))
print(f"检查3  菜单节点 {len(letters)} 个，连通分量 {len(components)} 个: "
      f"{[''.join(v) for v in components.values()]}")

# --- 检查 4：真密钥是否在 stop 里，其推导出的插线板是什么 ---
stops, _ = bombe(rotor_names, reflector_name, rings, ciphertext, crib, offset)
true_start = (ord("E") - A_CODE, ord("W") - A_CODE, ord("Q") - A_CODE)
print(f"检查4  真起始位置(右中左)={true_start} 是否在 {len(stops)} 个 stop 中: "
      f"{any(s[0] == true_start for s in stops)}")
for start, partner in stops:
    if start == true_start:
        derived = plugboard_from_partner(partner)
        print(f"       该 stop 的推导插线: {derived}")
        print(f"       真实插线:        {list(plug)}")
        undetermined = [chr(i + A_CODE) for i in range(26) if partner[i] == -1]
        print(f"       未确定伙伴的字母: {undetermined}")
