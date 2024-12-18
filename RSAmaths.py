# A full mathematical explanation of how & why RSA works
# illustrated with a trivial example.
# Note that even with these modest starting values some
# of the exponents get un-printably large and take a
# noticeable time to calculate. Things would speed up hugely
# were we to use the pow(b,e,u) function instead of the
# algebraic form b**e%u, but for the sake of clarity we'll
# stick with ** & % for this illustration.
# See also:
# https://doctrina.org/Why-RSA-Works-Three-Fundamental-Questions-Answered.html
# upon which this is based.

print('\nA trivial RSA example with step-by-step explanation...\n')

p = 199           # prime #1
q = 233           # prime #2
n = p*q           # public modulus
u = (p-1)*(q-1)   # the mysterious totient
e = 17            # public exponent
d = pow(e, -1, u) # private exponent
# remember d is calculated so that:
assert e*d % u == 1
# the totient u is crucial here, you'll see why later...
# check also that e does not divide into u
assert u %e != 0

m = 6789           # our private message, can be any +ve int < n
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

# EXPLANTION...

# encryption + decription can be summarised thus:
assert m == ( (m**e) %n )**d %n
# which (it can be shown) is equivalent to
assert m == (m**e)**d %n
# or, of course
assert m == m**(e*d) %n    # <2>
# but remember that
assert e*d % u == 1
# so therefor e*d = Ka * u + 1
# where Ka is some integer
# expanding u...
# e*d = Ka*(p-1)*(q-1) + 1
# so m**(e*d) = m**(Ka*(p-1)*(q-1) + 1)
#             = m * m**(Ka*(p-1)*(q-1))
#             = m * ( m**(Ka*(q-1)) )**(p-1)    <1>
# now we can apply Fermat's little theorem, which states:
# any-int-x ** (any-prime-p - 1) modulus p = 1
# for example:
assert m**(p-1) %p == 1
# or
assert e**(q-1) %q == 1
# now we can start to see why the totient is computed the way it is...
# for the 'little theorem' to be true we can see that
# any-int-x**(p-1) = Kb * p + 1 # where Kb is again some integer
# applying this to <1> above, and substituting ( m**(Ka*(q-1)) ) for any-int-x
# m**(e*d) = m * (Kb * p + 1), or
#          = (m * Kb * p) + m
# Ka has vanished - we never needed to know it
# Now taking mod p of both sides:
# m**(e*d) %p = ((m * Kb * p) + m) %p
#             = ((m * Kb * p) %p + m) %p
# but (any-int)*p %p = 0, so:
assert m**(e*d) %p == m %p  # <3>
# again Kb has vanished, we didn't need to know that either!
# similarly, we can do for q exactly what we did for p, re-arranging <1> slightly
#   m**(e*d) = m * ( m**(Ka*(p-1)) )**(q-1) allows us to write
assert m**(e*d) %q == m %q  # <4>
# now it can be shown that for any integers a,b and non-equal primes p,q:
#  IF a%p = b%p AND a%q = b%q THEN a%(p*q) = b%(p*q)
# sounds plausible, I've not seen a proof but have tested it numerically
# at great length and have never managed to find a counter example
# applying this rule to <3> and <4> above we can say
assert m**(e*d) %(p*q) == m %(p*q)
# but p*q is our public modulus n
assert p*q == n
# so we can avoid the use of our secret primes p & q during encryption and decryption
assert m**(e*d) %n == m %n
# as m < n from the ground rules of RSA we can obtain our original eqn <2>
assert m == m**(e*d) %n
print('\nBing-Pot!', m**(e*d)%n, '==', m, ' QED')
