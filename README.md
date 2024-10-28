# RSA cryptography in native python

A public key crypto system allows Alice to send a secret message to 
Bob through an open channel safe in the knowledge that only Bob can
read it - and _without_ requiring a pre-shared secret key.
Instead, Bob prepares in advance two (carefully chosen) keys, one
which he keeps secret and one which he openly publishes.
Alice can then use Bob's public key to encode her message, while Bob
uses his secret key to decode it. <b>It is not possible to decode the
message knowing only the public key</b>. It was the RSA algorithm that
first made this amazing feat possible.

Think about it, it really is amazing!

This script implements RSA key-generation, encyption and decryption in simple,
easily readable, commented native python code. No crypto libraries required,
just a random number source - encryption/decryption is migratable to microPython
but key generation is prohibitively time consuming when running on an ESP32. 

This is for illustrative purposes only, and is presented here in the
hope of illuminating the simplicity, mathematical beauty and sheer
genius of RSA cryptography.  Use in the real world at your own risk.

For a superb overview of all things crypto I can thoroughly recommend:
https://www.garykessler.net/library/crypto.html
