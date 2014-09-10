#!/usr/bin/env python3

import sys
from collections import defaultdict
from itertools import tee

english = "etaoinshrdlcumwfgypbvkjxqz"

ciphertext = sys.stdin.buffer.read()

d = defaultdict(int)

for c in ciphertext:
    d[c] += 1

for i,(k,v) in enumerate(sorted(d.items(), key=lambda vs: vs[1], reverse=True)):
    per = v / len(ciphertext)
    print("{}: {:2f}%".format(k, per))
