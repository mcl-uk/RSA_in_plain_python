# Public key cryptography explained
#
# A public key cryptography system allows Alice to send a secret message to Bob
# through an open channel safe in the knowledge that only Bob can read it - and
# without requiring a pre-shared secret key. Instead, Bob prepares in advance two
# carefully chosen keys, one of which he keeps secret and one which he openly publishes.
# Alice can then use Bob's public key to encode her message, while Bob uses his
# secret key to decode it. If the key is large enough it is not feasible to decode
# the message knowing only the public key. It was the RSA algorithm that first made
# this amazing feat possible. And it's still in use today at the bedrock of every-day
# internet security and authentication.  Note that RSA is only suited to encrypting
# relatively short messages and in fact is used mostly for key exchange to enable
# subsequent symetrically-encrypted communication eg using AES.
# Here I present a detailed, python-based, mathematical explanation of how & why the
# RSA algoritm works, illustrated by a simple key-generation/encrypt/decrypt example.
# Written by a non-mathematician for (python-literate) non-mathematicians, and
# without any of those wierd symbols or terminology that maths nerds like to use.
# Many thanks to:
# https://doctrina.org/Why-RSA-Works-Three-Fundamental-Questions-Answered.html
# upon which this is based.

print('\nA trivial RSA example with step-by-step explanation...\n')

# key generation...
p = 97            # choose two secret primes, #1
q = 233           # prime #2
n = p*q           # public modulus: 1st part of public key
                  # Note that for sufficiently large p & q it's not feasable
                  # to back-calculate them knowing only n, this is the keystone upon
                  # which RSA's security hangs. In the real world p & q would be many
                  # hundreds of digits long and also not be close neighbours.
u = (p-1)*(q-1)   # the 'totient', used during private key generation (keep it secret)
e = 17            # public exponent: 2nd part of public key, this can be any relatively
                  # small prime, but we must first check that e does not divide into u
assert u %e != 0  # - this is just one of the rules of RSA.
                  # 'assert' just means error out if the following expression is false

# now we can calculate our private key, d - an integer such that
#  (d*e) %u == 1
# d is called the 'multiplicative inverse' of e under modulus u, it can easily
# be calculated using the 'extended Euclidian algorithm' or more conveniently,
# in modern python implementations, we can just use the pow() function thusly:
d = pow(e, -1, u)
assert e*d %u == 1
# since this is such an important step let's get a better handle on it
# with some actual numbers so you can see how it plays out:
print(f'Check that e*d %u == 1: {e}*{d} = {e*d}, %{u} = {e*d %u} -- YES\n')
# the totient u is crucial here, you'll see why later...

# OK, we now have our public key (e & n) and our private key (d)
print('Public key:',(n,e), '\n')
# our private message, m, can be any +ve int < n-1
m = 6789
assert m < n-1

# Note that even with these relatively tiny numbers some of the intermediate values get
# un-printably large and take a noticeable time to calculate. This is because for clarity
# we're using ** for exponentiation and % for modulus as two separate steps.
# Modulo exponentiation is at the heart of RSA, it's pretty much all there is to it,
# both encryption and decryption are done with a single modulo exponentiation step,
# the genius of it is in the choice of keys - the exponents and the modulus.
# FYI Python's pow(a,b,c) function, which implements a**b %c in one highly optimised
# process is much much faster even when applied to very large numbers of 300+ digits.

print('message to send ', m)

# encrypt with public key:
cyphertext = m**e %n
print('cyphertext      ', cyphertext)

# decrypt with private key
mRx = cyphertext**d %n
print('message received', mRx)
print('\nchecking the maths step by step (may take afew seconds)...')
# check result
assert mRx == m

# But what was going on there and how does the maths of it work?
# Let's go take a closer look...

# encryption + decription can be summarised thus:
assert m == ( (m**e) %n )**d %n
# which is equivalent to
assert m == (m**e)**d %n
# this step may not be immediately obvious but it is the case that
# ((x %n)**y) %n == (x**y) %n, try a few simple examples, you'll see.
# or, of course
assert m == m**(e*d) %n    # <2>
# remember we calculated d so that
assert e*d %u == 1
# or in other words, to remove the modulus:
# e*d = Ka * u + 1,  where Ka is some integer
# we'll quickly calculate Ka but I've a feeling we won't utimately need it...
Ka = (e*d-1)//u  # we must use // here to keep Ka as an integer
assert e*d == Ka * u + 1
# expanding for u, exponentiating m and re-arranging...
assert e*d == Ka*(p-1)*(q-1) + 1
assert m**(e*d) == m**(Ka*(p-1)*(q-1) + 1)
assert m**(e*d) == m * m**(Ka*(p-1)*(q-1))
assert m**(e*d) == m * ( m**(Ka*(q-1)) )**(p-1)   # <1>
# feels like we made it a lot more complicated, but we're actually now
# in a good position to apply Fermat's little theorem, which states:
# (any-int-x ** (any-prime-p - 1)) modulus p = 1, unless x is some
# multiple of p in which case the result is zero - see footnote
# for example:
assert 12345**6 %7 == 1
assert e**(q-1) %q == 1
# with this in mind we apply mod p to both sides of <1> and get
assert m**(e*d) %p == m * ( m**(Ka*(q-1)) )**(p-1) %p
# now use the 'little theorem' to completely eliminate
# "( m**(Ka*(q-1)) )**(p-1) %p" which Fermat tells us is 1
# and so we get
assert m**(e*d) %p == m %p  # <3>
# abra-cadabra Ka and all that complication has gone, notice we
# must keep the %p on the rhs as x*y%p == (x%p) * (y%p) != x * (y%p)!
# looking again at <1>, we can re-arrange and apply the same logic
# we just used for p equally to q, yeilding:
assert m**(e*d) %q == m %q  # <4>
# now it can be shown that for any integers x,y and primes p,q:
#  if x %p == y %p and x %q == y %q then: x %(p*q) == y %(p*q)
# sounds plausible, I've not seen a proof but have tested it numerically
# at great length without ever finding a counter example
# applying this rule to <3> and <4> above we can say
assert m**(e*d) %(p*q) == m %(p*q)
# but p*q is our public modulus n, thus
assert m**(e*d) %n == m %n   # or since m < n...
assert m**(e*d) %n == m
# QED we just proved our original encrypt/decrypt equation <2>
print('\nBing-Pot!', m**(e*d)%n, '==', m, ' QED')
#
# It can now be seen that, with RSA, one can encrypt with either the
# private or public key, so long as you decrypt with the other key.
# Private key encryption is a great way of providing authentication. 
#
# Footnote:
# Interestingly the 'little theorem' zero case, resulting from the message
# m being a multiple of p or q, is perfectly consistent with this proof
# and does not break en/de-cryption. BUT the effects on the quality of the
# cypher-text are another matter, consider:
p,q,e = 97,233,17
message = 233*5 # or 97*12
cypher  = message**e %(p*q)
assert cypher == message
# The cypher-text is the same as the message, no encryption has happened!
# Other udesirable effects are the cypher being an integer muliple or
# fraction of the message. When scaled up to real-world key-lengths
# the issue is mitigated by the fact that the chances of the msg being
# a multiple of p or q aproximates to 2/sqrt(n) [where n = p*q]
# which would be an extremely small number, but not zero. Indeed
# finding such a message would grant easy access to the private key.
# Also, messages are always padded with plenty of random digits,
# which could be simply re-generated should the cypher turn out to
# be related to the msg in some simple way. 
# Alternatively if you keep the msg significantly shorter than
# sqrt(n) then there's no chance at all of it being a multiple of
# p or q. Eg for a 2048b key, maybe keep the msg+padding to under 1000
# bits - which of course is more than enough for a 256bit AES key
# suplemented by oodles of random padding.
# ---
# SJM Dec 24
# With profound respect to the geniuses who figured this out back in the 70's
