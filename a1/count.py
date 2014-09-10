#!/usr/bin/env python3

import sys
from collections import defaultdict
from itertools import tee

english = "etaoinshrdlcumwfgypbvkjxqz"

ciphertext = open('a1.cipher').read()
cleartext = ciphertext
ciphertext = ciphertext.replace('\n', '')

ln = len(ciphertext)

d = defaultdict(int)

for c in ciphertext:
    d[c] += 1

print("single letter freqs\n")

sed = []

for i,(k,v) in enumerate(sorted(d.items(), key=lambda vs: vs[1], reverse=True)):
    per = v / ln
    probs = english[i]
    sed.append("s/{}/{}/g".format(k, probs))
    print("{}: {:2f}% (probs {})".format(k, per, probs))
    cleartext = cleartext.replace(k, probs)

print("\n\ndouble letter freqs\n")

# straight from itertools
def pairwise(iterable):
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)

d = defaultdict(int)

for cc in pairwise(ciphertext):
    d[cc] += 1

doubs = []

for k,v in sorted(d.items(), key=lambda vs: vs[1], reverse=True):
    doub = k[0] + k[1]
    per = v / ln
    if k[0] == k[1]:
        doubs.append(k, per)
    if per < 0.02:
        break
    print("{}: {:2%}%".format(k, per))

if doubs:
    print("\n\nidentical doubles:")
    for doub in doubs:
        print("{}: {:2%}%".format(doub[0], doub[1]))

print("\nI think it's:")
print(cleartext)

print("\nsed script:")
for s in sed:
    print(s)
