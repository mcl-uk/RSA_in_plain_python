# A detailed, python-based, mathematical explanation of how & why RSA works,
# illustrated by a trivial key-generation/encrypt/decrypt example.
# Written by a non-mathematician for (python-literate) non-mathematicians, and
# without any of those wierd symbols or terminology that maths nerds use.
# Many thanks to:
# https://doctrina.org/Why-RSA-Works-Three-Fundamental-Questions-Answered.html
# upon which this is based.

print('\nA trivial RSA example with step-by-step explanation...\n')

# key generation...
p = 199           # choose two secret primes, #1
q = 233           # prime #2
n = p*q           # public modulus: 1st part of public key
                  # Note that for sufficiently large p & q it's not feasable
                  # to back-calculate them knowing only n, this is the keystone upon
                  # which RSA's security hangs.
u = (p-1)*(q-1)   # the 'totient', used during private key generation (keep it secret)
e = 17            # public exponent: 2nd part of public key, this can be any relatively
                  # small prime, but we must first check that e does not divide into u
                  # - this is just one of the rules of RSA.
assert u %e != 0

# now we can calculate our private key, d, we need to find an integer such that
# e*d %u == 1
# d is thus the 'multiplicative inverse' of e under modulus u (the totient)
# in modern python implementations we can use the pow() function to find it.
d = pow(e, -1, u)
assert e*d %u == 1
# check for yourself...
print(f'Check that e*d %u == 1: {e}*{d} = {e*d}, %{u} = {e*d %u} -- YES\n')
# the totient u is crucial here, you'll see why later...

# OK, we now have our public key (e & n) and our private key (d)
# our private message, can be any +ve int < n
m = 6789
assert m < n

# Note that even with these relatively tiny numbers some of the intermediate values get
# un-printably large and take a noticeable time to calculate. This is because for clarity
# we're using ** for exponentiation and % for modulus as two separate steps.
# Modulo exponentiation is at the heart of RSA, its pretty much all there is to it,
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
# (any-int-x ** (any-prime-p - 1)) modulus p = 1, for example:
assert 12345**6 %7 == 1
assert m**(p-1) %p == 1
assert e**(q-1) %q == 1
# with this in mind we apply mod p to both sides of <1> and get
assert m**(e*d) %p == m * ( m**(Ka*(q-1)) )**(p-1) %p
# now use the 'little theorem' to completely eliminate
# "( m**(Ka*(q-1)) )**(p-1) %p" which Fermat tells us is 1
assert m**(e*d) %p == m %p  # <3>
# abra-cadabra Ka and all that complication has gone, but note we
# must keep the %p on the rhs as x*y%p = (x%p) * (y%p) not x * (y%p)!
# looking again at <1>, we can re-arrange and apply the same logic
# we just used for p equally to q, yeilding:
assert m**(e*d) %q == m %q  # <4>
# now it can be shown that for any integers x,y and primes p,q:
#  if x %p == y %p and x %q == y %q then: x %(p*q) == y %(p*q)
# sounds plausible, I've not seen a proof but have tested it numerically
# at great length without ever fining a counter example
# applying this rule to <3> and <4> above we can say
assert m**(e*d) %(p*q) == m %(p*q)
# but p*q is our public modulus n, thus
assert m**(e*d) %n == m %n   # or since m < n...
assert m**(e*d) %n == m
# QED we just proved our original encrypt/decrypt equation <2>
print('\nBing-Pot!', m**(e*d)%n, '==', m, ' QED')
#
# One final note is that, with RSA, one can encrypt with either the
# private or public key, so long as you decrypt with the other key.
# Private key encryption is a great way of providing authentication. 
# ---
# With profound respect to the geniuses who figured this out back in the 70's
