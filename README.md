# VERUM
VERUM is a cryptographic primitives suite intended for mission-critical and safety-critical software. It is designed for configurability making it possible to prioritize performance or code size. The library emphasizes explicit assumptions, constant-time behavior, and formal reasoning about correctness.

Formal verification is used to establish functional correctness of the implemented primitives with respect to their specifications. Security, however, is not treated as an intrinsic property of the library in isolation. It emerges from correct composition, correct usage, and an accurate threat model within the surrounding system. Consequently, what constitutes “secure” is necessarily application-dependent.

VERUM makes a deliberate claim of correctness, not convenience.