# A detailed, python-based, mathematical explanation of how & why RSA works,
# illustrated by a trivial key-generation/encrypt/decrypt example.
# By a non-mathematician for other (python-literate) non-mathematicians.
# Note that even with these modest input values some of the exponents get un-printably
# large and take a noticeable time to calculate. Things would speed up hugely were we to use
# python's pow(b,e,u) function instead of the algebraic form b**e %u, but for the sake of clarity
# we'll stick with separate ** for exponentiation and % for modulus for this illustration.
# Such a form would of course be impractical for any kind of real-world implementation.
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
print('message to send ', m)

# encrypt with public key:
cyphertext = m**e %n
print('cyphertext      ', cyphertext)

# decrypt with private key
mRx = cyphertext**d %n
print('message received', mRx)

# check result
assert mRx == m

# But what was going on there and how does the maths of it work?
# Let's go take a closer look...

# encryption + decription can be summarised thus:
assert m == ( (m**e) %n )**d %n
# which is equivalent to
assert m == (m**e)**d %n
# this step may not be immediately obvious but there are plenty of proofs on the interweb
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
# that looks a lot more complicated, but we're actually in a good place
# because soon we can apply Fermat's little theorem, which states:
# (any-int-x ** (any-prime-p - 1)) modulus p = 1
# for example:
assert 12345**6 %7 == 1
assert m**(p-1) %p == 1
assert e**(q-1) %q == 1
# with this in mind we apply mod p to both sides of <1> and get
assert m**(e*d) %p == m * ( m**(Ka*(q-1)) )**(p-1) %p
# now use the 'little theorem' to completely eliminate
# "( m**(Ka*(q-1)) )**(p-1) %p" which Fermat tells us is 1 
assert m**(e*d) %p == m %p  # <3>
# abra-cadabra Ka has gone
# looking again at <1>, we can re-arrange and apply the same logic
# we just used for p equally to q, yeilding:
assert m**(e*d) %q == m %q  # <4>
# It can be shown that for any integer x and primes p,q:
#  if x %p == y %p and x %q == y %q then: x %(p*q) == y %(p*q)
# sounds plausible, I've not seen a proof but have tested it numerically at
# great length without ever fining a counter example
# applying this rule to <3> and <4> above we can say
assert m**(e*d) %(p*q) == m %(p*q)
# but p*q is our public modulus n, thus
assert m**(e*d) %n == m %n
assert m**(e*d) %n == m   # since m < n
# we just derived & proved our original encrypt/decrypt equation <2>
print('\nBing-Pot!', m**(e*d)%n, '==', m, ' QED')
#
# with profound respect to the geniuses who figured this out back in the 70's
