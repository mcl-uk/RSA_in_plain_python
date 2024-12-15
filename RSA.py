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
# This script implements RSA key-generation, encryption and decryption in
# relatively simple, easily readable, commented native python code.
# It works on microPython too, but key generation is going to be very
# time consumimg on a microcontroller. Eg an ESP32 may thake many minutes
# to find even a relatively small 1024bit key.
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
# and provides the essential (third) modulus argument. Note that an equivalent
# function exists in php: gmp-powm(), it requires extension=gmp; in php.ini.
#
# Also note that we can encrypt with either the private OR public keys so long as
# we subsequently decrypt with the _other_ key.
#
# Normally (eg secret key transmission) we'd encrypt with public and decrypt
# with private keys but the other way round has many uses in authentication
# applications eg signing documents etc.


#import base64 utilities
try: # regular Python
    from base64 import b64encode
    from base64 import b64decode
except: # microPython
    from ubinascii import b2a_base64 as b64encode
    from ubinascii import a2b_base64 as b64decode

# Key generation on a microcontroller can be very slow
# especially for larger key sizes.
KEY_SIZE = 1024 # eg 1024, 2048, 3072

# Arbitrary integer test 'message', change at will
# should be of shorter bit-length than KEY_SIZE
MSG = 1234567890123456789012345678901234

# -------- some supporting functions ---------------------

# microPython does not support int.bit_length()
def bitLen(n):
    return len(bin(n))-2

def bytLen(n):
    return (len(hex(n))-1)//2

# As the name suggests, but dont use with -ve numbers
def bigInt2Bytes(bigI):
    return bigI.to_bytes(bytLen(bigI), 'big')

# Base64 encode a (long) +ve integer
def bigInt2B64(bigInt):
    return b64encode(bigInt2Bytes(bigInt)).decode('utf-8')

# Decode a base64 string to a (long) integer (+ve only)
def B642bigInt(strIn):
    return int.from_bytes(b64decode(strIn), 'big')

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
    from os import urandom as randBytes
    #
    def randBelow(n):
        rnd = int.from_bytes(randBytes(bytLen(n)), 'big')
        while rnd > n: rnd >>= 1 
        return rnd
    #
    # Use a miller-rabin test [scrounged from the internet] to _statistically_ test a number for
    # probable primality - to a programmable degree of certainty (govered by k below)
    def IsPrime(n):
        # miller-rabin test...
        def millerTest(d, n):    
            a = 2 + randBelow(n - 4)
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
    # Hunt for primes - SLOW!
    def getBigPrime(nBits):
        n = int.from_bytes(randBytes(nBits//8), 'big') | 1
        while not IsPrime(n): n += 2
        return n
    #
    # A minimal implemetation of the "extended euclidean algorithm" to find
    # the "multiplicative inverse" of e mod u
    # Equivalent to pow(e, -1, u) - not supported in older Pythons or uPy
    # Note that if u is prime we could use pow(e, p-2, p) as an alternative.
    def eea(e, u):
        a,b = e,u
        cd  = [(1,0),(0,1),(0,0)]
        while b > 0:
            q,r = a//b, a%b
            cd[2] = (cd[0][0]-q*cd[1][0], cd[0][1]-q*cd[1][1])
            for i in (0,1): cd[i] = cd[i+1]
            a,b = b,r
        if a != 1: return None # Impossible
        return cd[0][0]%u;
    #
    # OK, Find two big primes (should not be 'close' to one-another)...
    # Note: "with current factorization technology, the advantage
    # of using 'safe' or 'strong' primes appears to be negligible" [wikipedia]
    #
    p = getBigPrime((KEY_SIZE//2)+1)
    q = getBigPrime((KEY_SIZE//2)-1)
    #
    # Create the public key, comprising two integers n & e, n is
    # the modulus and e is the exponent.
    #
    n = p * q
    #
    # The strength of RSA rests on the computational difficulty of
    # factoring n (above) ie finding the original p & q.
    # Should it ever become possible to factor arbitrarily long
    # numbers then RSA will become history. In the meantime
    # we can appreciate its elegance every time we use it.
    # As an intermediate step we now compute the totient u
    #
    u = (p - 1) * (q - 1)
    #
    # Now we need an arbirary prime e that is also prime to the totient.
    # The value 65537 is widely used for the exponent but we must make
    # sure it wont divide into our chosen u, if by chance it does we
    # just move on until we find another prime that doesn't.
    #
    e = 65537
    while (u % e == 0) or (not IsPrime(e)): e += 2
    #
    # Now we can create the private key...
    # Find an integer d such that (d*e) % u == 1
    # d is the "multiplicative-inverse" of e in mod u arithmetic.
    # d = pow(e, -1, u), or for microPython compatability we can
    # use the extended euclidean algorithm to find d
    #
    d = eea(e, u) 
    #
    return (n,e,d)  # return key-set


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
