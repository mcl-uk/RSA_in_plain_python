
# Example RSA public-key functions in _native_ python
#
# Sept 2024  SJM at MarvellConsultants.com
#
# A public key crypto system allows Alice to send a secret message to 
# Bob through an open channel safe in the knowledge that only Bob can
# read it - but WITHOUT them having to pre-share a secret key.
# Instead, Bob prepares in advance two (carefully chosen) keys, one
# which he keeps secret and one which he openly publishes.
# Alice can then use Bob's public key to encode her message, while Bob
# uses his secret key to decode it. It is not possible to decode the
# message knowing only the public key. It was the RSA algorithm that
# first made this amazing feat possible.
#
# Think about it, it really is amazing!
#
# This script implements RSA encyption and decryption in simple,
# easily readable, commented native python code. No crypto libraries
# are required and it's even migratable to microPython.
#
# It also illustates key generation using just a couple of primitive
# functions from pycryptodome.
# So you will need to pip install pycryptodome to run this script
#
# This is for illustrative purposes only, and is presented here in the
# hope of shining a light on the simplicity, mathematical beauty and sheer
# genius of RSA cryptography.
#
# Use in the real world at your own risk.
#
# For a superb overview of all things crypto I can thoroughly recommend:
# https://www.garykessler.net/library/crypto.html

import base64  # Assumes the reader is familiar with base64 encoding
# This lib is used only for illustative purposes

# This lib is only required for key generation
from Crypto.Math import Primality
# pip install pycryptodome

# Arbitrary integer test 'message', change at will
MSG = 9765245987065408765087654320876543098736409876543

# -------- some supporting functions ---------------------

# As the name suggests, but dont use with -ve numbers
def bigInt2Bytes(bigI):
    i = bigI
    op = b''
    while i > 0:
        by = i % 256
        i = i >> 8
        op = by.to_bytes() + op
    return op

# As the name suggests
def Bytes2bigInt(bs):
    op = 0
    for i in bs: op = (op << 8) + i
    return op

# Base64 encode a (long) +ve integer
def bigInt2B64(bigInt):
    return base64.b64encode(bigInt2Bytes(bigInt)).decode('utf-8')

# Decode a base64 string to a (long) integer (+ve only)
def B642bigInt(strIn):
    return Bytes2bigInt(base64.b64decode(strIn))

# Split a long string into chunks for printing
def chunkify(txt, width):
    chunks = []
    for i in range(0, len(txt), width):
        chunks.append(txt[i:i+width])
    return '\n'.join(chunks)

# Used only during key generation:
# This here's some serious black magic scrounged from the internet.
# Minimal implemetation of the "extended euclidean algorithm" to find
# the "multiplicative inverse" of the public key e wrt modulus u
def eea(x, mod): # (e,u)
    a,b,c1,d1,c2,d2 = x,mod,1,0,0,1
    while b > 0:
        q,  r  = a//b, a%b
        c3, d3 = c1-q*c2, d1-q*d2
        c1, d1 = c2, d2
        c2, d2 = c3, d3
        a,  b  = b , r
    if a != 1: return None # Impossible
    return c1;

# Generate a private/public key pair,
# On error retun d = None (couldn't find a solution, re-try)
# Std key-sizes are 1024bits (good), 2048 (better), 3072 (unecessary)
def keyGen(keySize=1024): # keySize in bits
    # Find two big primes (should not be 'close' to one-another)...
    while True:
        p = int(Primality.generate_probable_prime(exact_bits=(keySize//2)+1))
        if Primality.lucas_test(p) != 1: continue
        if Primality.miller_rabin_test(p, 64) == 1: break
    while True:
        q = int(Primality.generate_probable_prime(exact_bits=(keySize//2)-1))
        if Primality.lucas_test(p) != 1: continue 
        if Primality.miller_rabin_test(p, 64) == 1: break
    #
    # Create the public key, comprising two integers n & e...
    n = p * q
    #
    # The strength of RSA rests on the computational difficulty of
    # factoring n (above) ie finding the original p & q.
    # Should it ever become possible to factor a 2048 bit (640 decimal
    # digit) number then RSA will become just history. In the meantime
    # we should apreciate its elegance every time we use it.
    #
    u = (p - 1) * (q - 1) # the 'modulus'
    #
    # Now come up with an arbirary prime e that is also prime to the modulus.
    # The value 65537 is widely used for the public key but we must make
    # sure it wont divide into our chosen modulus, if by chance it does we
    # just move on until we find another prime that doesn't.
    e = 65537 # standard initial try _almost_ always adequate
    while (u % e == 0) or (Primality.lucas_test(e) != 1): e += 2 # re-try
    #
    # Now we can create the private key, a bit trickier...
    # Find an integer d such that (d*e) % u == 1
    d = eea(e, u) # returns None if (impossibly) no result exists
    # Private Key is d (used together with n from the public key).
    # Note that d is slightly smaller than n and be -ve
    return (n,e,d)


# --------- MAIN ---------------------------

# First, make a new key pair that we can use in our demo...
# The public key is actually two integers, n & e - one very large, one
# small: n is the product of 2 large primes and e is _usually_ 65537.
# The private key is also a very large integer, d - it must also be used
# in conjunction with n.
# Here "very large" means beyond the scope of practical factorisation.

print('Generating new key pair...')
d = None
while d is None:
    n,e,d = keyGen(2048) # create an 2048-bit public/private key pair
    if d is None: print("Math problem, this shouldn't happen")
# Note that d can be a negative number!

# Make a more compact text version of the public key for distribution
pubKey = f"{bigInt2B64(n)},{bigInt2B64(e)}"
print(f"Public Key (n,e):\n{chunkify(pubKey, 72)}")
print(f"Private Key (d): It's a secret, but it's {len(str(abs(d)))} decimal digits")
# The private key can be -ve so can't simply be base64'd

print()
print('Testing...')
print()

# As an example we'll use the public/private keys we just made to encrypt a long(ish)
# integer 'message' with our private key and then decrypt it with the public key.
# As that would only be two lines of code we'll make it bit more real-world by
# encoding the public key and the cypher text into base64 for display (and pretend
# transmission) then decode back again for decryption.
#
# Astonishingly encryption and decryption are both simply 1-line invocations of
# python's native pow() function. It which works with integers of arbitaray length
# and provides the essential (third) modulus argument.
#
# Also note that we can encrypt with either the private OR public keys so long as
# we subsequently decrypt with the _other_ key.
#
# Normally (eg secret key transmission) we'd encrypt with public and decrypt
# with private keys but the other way round has many uses in authentication
# applications eg signing documents etc.

print(f"Message input:     {MSG}") # from top of the script

# Encrypt (note all inputs and outputs are integers)...
cypherN = pow(MSG, d, n) # encrypt with private key (d)
# Yes, that it!

# Convert cypherN integer to base64 text
cypherText = bigInt2B64(cypherN)
print(f"\nCypher-Text:\n{chunkify(cypherText,72)}\n")
# Pretend to transmit cypher text
# ...
# And receive the base64 cypher text, converting it back to integer form
cypherRx = B642bigInt(cypherText)
# re-create the public key integers from the base64 encoded pubKey
try:
    pkTmp = pubKey.split(',')
    assert len(pkTmp) == 2
    N,E = B642bigInt(pkTmp[0]), B642bigInt(pkTmp[1])
except:
    raise ValueError('Bad public key!')

# Decrypt using the public key (all inputs and outputs are integers)...
output = pow(cypherRx, E, N) # decrypt with recovered public key (N,E)
# Again that's all there is to it!

print(f"Decrypted output:  {output}")



