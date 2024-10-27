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
# This script implements RSA key-generation, encyption and decryption in
# relatively simple, easily readable, commented native python code.
# No crypto libraries are required, just a random number source,
# it's even migratable to microPython.
#
# This is for illustrative purposes only, and is presented here in the
# hope of iluminating the simplicity, mathematical beauty and sheer
# genius of RSA cryptography. Use in the real world at your own risk.
#
# For a superb overview of all things crypto I can thoroughly recommend:
# https://www.garykessler.net/library/crypto.html
#
# As an example we'll create a pair of public/private keys and encrypt a long(ish)
# integer 'message' with the private key and then decrypt it with the public key.
# As that would only be three lines of code we'll make it a bit more real-world by
# encoding the public key and the cypher text into base64 for display (and pretend
# transmission) then decode back again for decryption.
#
# Astonishingly encryption and decryption are both simply 1-line invocations of
# python's native pow() function. It works with integers of arbitaray length
# and provides the essential (third) modulus argument.
#
# Also note that we can encrypt with either the private OR public keys so long as
# we subsequently decrypt with the _other_ key.
#
# Normally (eg secret key transmission) we'd encrypt with public and decrypt
# with private keys but the other way round has many uses in authentication
# applications eg signing documents etc.

import base64  # Assumes the reader is familiar with base64 encoding

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

# Generate a private/public key pair,
# On error retun d = None (couldn't find a solution, re-try)
# Std key-sizes are 1024bits (good), 2048 (better), 3072 (unecessary)
def keyGen(keySize=1024): # keySize in bits
    import secrets  # just as a source of random numbers, I can't speak for the quality of these numbers
                    # and it doesn't matter for the sake of this illustration but in a production envir-
                    # onment you'd want to make sure this was a cryptographically sound random source.
    #
    # Use a miller-rabin test [scrounged from the internet] to _statistically_ test a number for
    # probable primality - to a programmable degree of certainty (govered by k below)
    def IsPrime(n):
        # miller-rabin test...
        def millerTest(d, n):    
            a = 2 + secrets.randbelow(n - 4)
            x = pow(a, d, n)
            if (x == 1) or (x == n-1): return True
            while (d != n-1):
                x = (x * x) % n
                d *= 2
                if (x == 1): return False
                if (x == n-1): return True
            return False
        #
        k = min(int(len(str(n))/5)+4, 64) # no of itterations
        if n <= 3: return n > 1
        if (n&1 == 0): return False
        d = n - 1
        while (d % 2 == 0): d //= 2
        for i in range(k):
            if millerTest(d, n) == False: return False
        return True
    #
    # sieve the ocean for primes
    def getBigPrime(nBits):
        n = secrets.randbits(nBits)
        while not IsPrime(n): n = secrets.randbits(nBits)
        return n
    #
    # OK, Find two big primes (should not be 'close' to one-another)...
    # Note: "with current factorization technology, the advantage
    # of using 'safe' or 'strong' primes appears to be negligible" [wikipedia]
    #
    p = getBigPrime((keySize//2)+1)
    q = getBigPrime((keySize//2)-1)
    #
    # Create the public key, comprising two integers n & e...
    #
    n = p * q
    #
    # The strength of RSA rests on the computational difficulty of
    # factoring n (above) ie finding the original p & q.
    # Should it ever become possible to factor arbitrarily long
    # numbers then RSA will become history. In the meantime
    # we can apreciate its elegance every time we use it.
    #
    u = (p - 1) * (q - 1) # the 'modulus'
    #
    # Now come up with an arbirary prime e that is also prime to the modulus.
    # The value 65537 is widely used for the public key but we must make
    # sure it wont divide into our chosen modulus, if by chance it does we
    # just move on until we find another prime that doesn't.
    #
    e = 65537 # standard initial try _almost_ always adequate
    while (u % e == 0) or (not IsPrime(e)): e += 2 # re-try
    #
    # Now we can create the private key...
    # Find an integer d such that (d*e) % u == 1
    # d is the "multiplicative-inverse" of e in mod u arithmetic
    # we can use the pow() function to calculate it.
    #
    d = pow(e, -1, u)
    #
    # Private Key is d (used together with n from the public key).
    # Note that d is slightly smaller than n
    #
    return (n,e,d)


# --------- MAIN ---------------------------

# First, make a new key pair that we can use in our demo...
# The public key is actually two integers, n & e - one very large, one
# small: n is the product of 2 large primes and e is _usually_ 65537.
# The private key is also a very large integer, d - it must also be used
# in conjunction with n.
# Here "very large" means beyond the scope of practical factorisation.

print('Generating new key pair...')
n,e,d = keyGen(2048) # create a 2048-bit public/private key pair

# Make a more compact text version of the public key for distribution
pubKey = f"{bigInt2B64(n)},{bigInt2B64(e)}"
print(f"Public Key (n,e):\n{chunkify(pubKey, 72)}")
print(f"Private Key (d): It's a secret, but it's {len(str(abs(d)))} decimal digits")

print()
print('Encypt / decrypt demo...')
print()

print(f"Message input:     {MSG}") # from top of the script

# Encrypt (note all inputs and outputs are integers)...
cypherN = pow(MSG, d, n) # encrypt with private key (d)
# Yes, that's it!

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
