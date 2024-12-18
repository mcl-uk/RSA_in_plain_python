# RSA cryptography in native python

A public key crypto system allows Alice to send a secret message to Bob through an open channel safe in the knowledge that only Bob can read it - and _without_ requiring a pre-shared secret key.
Instead, Bob prepares in advance two (carefully chosen) keys, one which he keeps secret and one which he openly publishes.
Alice can then use Bob's public key to encode her message, while Bob uses his secret key to decode it.
<b>If the key is large enough it is not feasible to decode the message knowing only the public key</b>.
It was the RSA algorithm that first made this amazing feat possible.

Think about it, it really is amazing!

The RSA.py script implements 2048-bit RSA key-generation, encryption and decryption in simple, easily readable, commented native python / microPython code.
RSAmaths.py offers a detailed, step-by-step explanation of how and why the maths works illustrated by a small-scale example.
RSA.py will work on microPython, no crypto libraries are required, just a random number source. Note that key generation can be very slow on a microcontroller,
for example an ESP32 may take many minutes to find a 1024bit key-set, maybe see my elliptic curve demo for a more practical scheme for microcontrollers.

This is all of course for illustrative purposes only, and is presented here in the hope of illuminating the simplicity, mathematical beauty and sheer genius of RSA cryptography.
Use in the real world at your own risk.

For a superb overview of all things crypto I can thoroughly recommend:
https://www.garykessler.net/library/crypto.html
And for RSA in particular:
https://doctrina.org/Why-RSA-Works-Three-Fundamental-Questions-Answered.html
