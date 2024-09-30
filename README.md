# RSA_in_plain_python

Example RSA public-key functions in _native_ python
A public key crypto system allows Alice to send a secret message to 
Bob through an open channel safe in the knowledge that only Bob can
read it - but WITHOUT them having to pre-share a secret key.
Instead, Bob prepares in advance two (carefully chosen) keys, one
which he keeps secret and one which he openly publishes.
Alice can then use Bob's public key to encode her message, while Bob
uses his secret key to decode it. It is not possible to decode the
message knowing only the public key. It was the RSA algorithm that
first made this amazing feat possible.

Think about it, it really is amazing!

This script implements RSA key-generation, encyption and decryption in simple,
easily readable, commented native python code. No crypto libraries are required,
just a random number source - it's even migratable to microPython.

This is for illustrative purposes only, and is presented here in the
hope of illuminating the simplicity, mathematical beauty and sheer
genius of RSA cryptography.

Use in the real world at your own risk.

For a superb overview of all things crypto I can thoroughly recommend:
https://www.garykessler.net/library/crypto.html
