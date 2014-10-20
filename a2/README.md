Assignment 2
============

The attack is simple. Since there are only 256 possible messages, and the
encryption key is public, we can encrypt every possible message and compare
the ciphertexts with our plaintexts to recover the message. This is
implemented in `src/main.rs`.
