Corey Richardson
9/9/2014
CS456

1. The substitution table:

```
A = T
B = H
C = L
D = R
E = F
F = O
G = I
H = N
I = G
J = ?
K = V
L = B
M = Q
N = U
O = J
P = Z
Q = ?
R = M
S = Y
T = C
U = P
V = S
W = W
X = E
Y = X
Z = ?
```

Since three letters were unused, those mappings are unknown but irrelevant and
easy to deduce from more ciphertext containing those characters.

2. I took two approaches. First, I wrote the script found here (count.py)
   which uses single- and double-letter frequences. It isn't very smart,
   and produces wrong results. Then, I wrote the bruteforcer found adjacent.
   It iterates over all 26! possible keys and tries each one, doing the
   substitution and searching for the substring "crypto". By luck, that
   substring actually appeared in the plaintext, so it would have eventually
   terminated, but not before the sun burned out a few times over. So I went
   back to count.py, took the few most frequent letters, and stared at it
   until some real words popped out.

3. The CCS (cmr cipher system) takes as input an 8-byte key, of which none of
   the bytes can be zero. This is taken as the seed to a XorShift64\* [1]
   pseudorandom number generator. The input text is split into 8-byte chunks.
   If the number of input bytes is not a multiple of 8, the last chunk has
   zeros appended to it until it is 8 bytes long. Then, the ciphertext is
   created by doing a bitwise XOR on each plaintext chunk with the output of
   the PRNG. Se `ccs.rs` for a Rust implementation.

Example:

```
$ rustc ccs.rs
$ ./ccs hidetext < ciphertext.txt | base64
MPDvNcM3F2lrKhYlhA46q/RfQ9mE3aAJrloraPW78MYnuWzJokLsNUSAn2Dwkx4nTTy2LpeKSZY/
j481KafR20qmb3oyXMN6YooNxN5Es1GT1CTkFH2j+oIe5cpLJ7TpTpAvFg34vd8IkYbDT1g4bKJ7
7SwzFRto9OzUdsv1qSVhrsUYMOS7REWMppLWTmQ4DIkeYkmLibvjI6XRbUP9YugOLkvFGIGAl44G
BzW2O2zRLe6oJT2TTf1ywa9OsrRBoi9fqBtrWdiG8Vox2OIzrwGggH6JatUjhfv8nZLuHKKjYRJc
6npsPWqlQdLShwU3UpdoNnfYiSM3n6Tm/y4wuGdKZKCMFPe8tDEFp2owPCrWBzwUkIgCQbQg987h
1WSqT4bhWDQ8pawzX2GGxolULU4YprtZqIYfG006xEAKkO5TvUVFXIqr7zcp6+mvDM6pm3LjZzpY
mBocAw+V0hPqPaRBjBQaMy0WIEkp+3+AhOlcYsIA1RUmKG5V8Eqf3NFAjO0kY/2QwiHZBrp342QB
y6CTVwlnLk8Q+aNysxxqfE/5F/LjONhYMErikurASxB5yf326z2jg/Byp7Ccl715uvVLXrGskLmL
J0tVeinNtDtUsYyRuP/OBsp2a4gq14tI8Pfov36CqRPZ4AB7uJFqiD1Q5szL0mVCzsTQP/A2XRPo
BakYAfCTP6xqQGnYvuXRKyMJhRozkAmuDpMi1s2ZKRy7tePCEPCu3wiDqduQhqyPKlBAs/Ds/kkL
WQSJopv2BtnsXWATHcVfmCU2BWLcS1yE7xjQsNJH3MqIfYGBfyEQfVWImEDPQE6td/5t7h56WWYh
/DmUOqjEuo0cdy/QyrCrDZo5h/CjRS2PKQuMv9bLZvZ1PbnM7vrdX9k9q9f4Znggp53TaxKE/+4n
/Ad/ey+3IpRLqM6r6L/IGq4+Ar3kXkEwG3+4jMzW7r6qRg1lZVkBml1HZw/OhWKFOR6lwMFR5rci
8gqMspAuBA1RVgpS56hL6cp7dpJvPx0aKN0VOueGSqxuyozwdIouGAxF9w/NinOwyQ1OjqSbqNHv
QwGNJ8jWvRz8eYJbBY8NBLYhnRisXFhFMVUrR3rZR8FGA0APtU5hQJVWZdd2bZ5phl5FN+VPCViQ
qN5/gafP8cnNLmqDIwkimFNsPHXpuWeLCg==
$
```

Doing a simple analysis of the byte frequency of the encrypted text indicates
that it is not quite uniform, but the distribution is better than the simple
monoalphabetic cipher.

4. Using the table provided at
   http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_other_languages,
   English seems to have one of the worst letter frequencies, in terms of
   deviation from uniform.

- [1]: arXiv:1402.6246 (http://arxiv.org/abs/1402.6246)
