"""
https://en.wikipedia.org/wiki/RSA_(cryptosystem)

Prior to the 1970s, all encryption schemes required some kind of pre-shared secret (cipher).

Some of the underlying number theory has been studied for 1200+ years but applications
for it in cryptography were only found much more recently. 
"""

import sympy
import math
import hashlib
import timeit

def generate_modulus(p=None, q=None):
    """
    Calculate the product (n) of two primes (p,q) where p,q will be kept secret.
    Returns the publically shared public/private key modulus n
    Where the bit length of n is the key length which is the primary factor in its strength
    """
    # In practice these should be much larger and picked from a secure 
    # standard like Oakley or Safe Prime Groups with a large and random difference
    # https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
    if p is None:
        # primes are generated via random ints then testing for primality
        p = sympy.randprime(MIN_PRIME, MAX_PRIME)
    else:
        # One approach for testing primality is dividing the number by every integer 
        # from 2 up to the square root of the number. If none of these divisions result 
        # in a whole number quotient, then the number is prime.
        if not sympy.isprime(p):
            raise RuntimeError("Selected p was not prime")
        
    if q is None:
        q = sympy.randprime(MIN_PRIME, MAX_PRIME)
    else:
        if not sympy.isprime(q):
            raise RuntimeError("Selected q was not prime")
        if p == q:
            raise RuntimeError("p & q must be distinct")

    while p == q:
        # if collision with no preset, recursively try again
        # if infinite collision recursion limit will be reached
        return generate_modulus()

    return p, q, int(p * q) # type: ignore

def calculate_totient(p, q):
    """
    Calculate the totient of the modulus
    """
    # could use Euler's Totient when factorization of n is two distinct primes
    # however this is not feasible to compute for large primes
    # https://en.wikipedia.org/wiki/Euler%27s_totient_function
    # phi = sympy.totient(p*q)

    # for RSA modulii this can more simply/feasibly 
    # be expressed with knowledge of p & q as:
    phi = (p-1) * (q-1)

    # can also use Carmichael function λ(n) (least universal exponent)
    # if factorization of n is unknown but this is similarly not feasible 
    # to compute for large primes
    # https://en.wikipedia.org/wiki/Carmichael_function
    # phi = sympy.ntheory.factor_.reduced_totient(p*q)

    return phi

def calculate_public_exponent(phi):
    """
    Calculate the public key exponent as a coprime of n
    will be shared publically as the public key exponent e
    """
    # generate a coprime between 1 and λ(n)
    # https://en.wikipedia.org/wiki/Coprime_integers
    e = sympy.randprime(1, phi)
    while math.gcd(e, phi) != 1: # type: ignore
        # if no possible match recursion limit will be reached
        return calculate_public_exponent(phi)
    
    return int(e) # type: ignore

def calculate_private_exponent(phi, e):
    """
    Calculate the private key exponent d (secret)
    As the modular multiplicative inverse of e modulo phi
    """
    # compute the modular multiplicative inverse of the public exponent modulo phi
    # extended euclidean algorithm
    # returns x, y & gcd(a,b) 
    # where x, y are coefficients in Bézout's identity ax + by = gcd(a,b)
    # https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    # https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity
    x, _, gcd = sympy.gcdex(e, phi)
    
    if gcd != 1:
        raise ValueError(f"e and phi are not coprime")
    
    return int(x % phi) # type: ignore

def encode_string(s, encoding="utf-8", hash=None, payload=None):
    """
    Encode a string as an integer
    Additionally generate & encode a hash for the encoded string
    Optionally override the hash or payload with a preset value

    For a single char string this is effectively the same as calling ord(s)
    ord("A") = 65 = 01000001

    Where a multi char string "AA" is represented as
    16705 = 01000001 01000001 = "AA"
    """
    if payload is None:
        s_bytes = s.encode(encoding) # string -> bytes
    else:
        s_bytes = payload
    
    s_int = int.from_bytes(s_bytes, byteorder="big") # bytes -> int
    s_hash = hashlib.sha256(s_bytes).digest() # bytes

    if hash is None:
        hash_int = int.from_bytes(s_hash, byteorder="big") # bytes -> int
    else:
        hash_int = int.from_bytes(hash, byteorder="big") # bytes -> int

    return s_int, hash_int

def decode_int_to_bytes(i):
    # int -> bytes, ensuring any modulo is padded into new byte
    # (if there's no modulo the padding will be discarded by the floor division)
    return i.to_bytes(((i.bit_length() + 7) // 8), byteorder="big")

def decode_string(s_int, encoding="utf-8", hash=None, payload=None):
    """
    Decode a previously encoded string from integer back into a string
    Generate a hash from the encoded message prior to decode
    Optionally override the hash value with a preset value

    For an int representing a single encoded char this is effectively 
    the same as calling chr(s_int) where
    chr(65) = "A" = 01000001 

    Like  the encoding example a multi char string "AA" is also represented as
    16705 = 01000001 01000001 = "AA"
    """
    s_bytes = decode_int_to_bytes(s_int)
    
    if hash is None:
        s_hash = hashlib.sha256(s_bytes).digest() # bytes
    else:
        s_hash = hash

    if payload is None:
        s_str = s_bytes.decode(encoding) # bytes -> string
    else:
        s_str = payload

    return s_str, s_hash

def decode_hash(h):
    """
    Decode a previously encoded hash from integer back into bytes
    """
    return decode_int_to_bytes(h)

def encrypt_message(m, n, e):
    """
    Encrypt the encoded form of the plaintext m with modulus n and 
    public exponent e with the modular exponentiation function m^e mod n
    Where m is the encoded integer form of the plaintext
    https://en.wikipedia.org/wiki/Modular_exponentiation
    """
    # Note: in all forms of this function there is a drastic computational
    # difference in cost between a^b mod c and pow(a, b, c)
    # m^e mod n
    return pow(m, e, n)

def decrypt_message(c, n, d):
    """
    Decrypt the ciphertext c into encoded plaintext with modulus n and private exponent d
    Similar modular exponentiation function to above: c^d mod n
    """
    # c^d mod n
    return pow(c, d, n)

def encrypt_hash(h, n, d):
    """
    Generate a signature by encrypting the hash of the message
    Encrypt the hash with the private key (reverse of ciphertext process)
    In this instance its intended to be decrypted with the public key
    So only public information (i.e. the hash) should be encrypted this way
    Similar modular exponentiation function to above: c^d mod n
    """
    # h^d mod n
    return pow(h, d, n)

def decrypt_hash(h, n, e):
    """
    Decrypt the hash h with the public key
    Similar modular exponentiation function to above: h^e mod n
    """
    # h^e mod n
    return pow(h, e, n)

def validate_signature(local_hash, remote_hash):
    return local_hash == remote_hash

def generate_exponents(p, q, e):
    """
    Generate p, q prime factors
    Calculate Euler's Totient phi(p*q)
    Generate public exponent e(phi)
    Generate private exponent d(phi, e)
    """
    preset_pq = p or q
    preset_e = e is not None

    # generate random, unique primes
    # test for primality + uniqueness if preset
    p, q, n = generate_modulus(p=p, q=q)
     
    # Euler's Totient
    phi = calculate_totient(p, q)

    if preset_e:
        if not sympy.isprime(e):
            raise RuntimeError("e must be prime")
    else:
        # generate an exponent enforcing its coprimality to phi
        # chosen randomly from range 1 to phi
        e = calculate_public_exponent(phi)

    if preset_pq:
        if preset_e:
            # if all selected manually, test coprimality
            # https://en.wikipedia.org/wiki/Euclidean_algorithm
            if math.gcd(e, phi) != 1: # type: ignore
                raise RuntimeError("Preset exponent e was not coprime to λ(n)")
        
    else:
        if preset_e:
            # if phi isn't coprime to e, attempt to generate new p,q > phi
            attempts = 0
            while math.gcd(e, phi) != 1:
                if attempts > 1000:
                    raise RuntimeError("Unable to generate new coprime for λ(n) from e")
                p, q, n = generate_modulus()
                phi = calculate_totient(p, q)
                attempts += 1
        else:
            # if phi isn't coprime to e, attempt to generate new e
            while math.gcd(e, phi) != 1:
                e = calculate_public_exponent(phi)
    
    d = calculate_private_exponent(phi, e)
    return n, e, d, phi

if __name__ == "__main__":
    # p/q must unique primes, e is recommended to be small odd prime
    # p = 61; q = 53; e = 17; original_plaintext = "A" # ord("A") == chr(65), wikipedia example
    p = None; q = None; e = 7; original_plaintext = "DEADBEEF"*4 # message length == sha-256 hexdigest

    encoding = "utf-8"
    hash = None # b'X'
    payload = None # decode_int_to_bytes(255)

    # fiddle with some constants for message/key size
    # n key size must be > message size
    msg_len = len(original_plaintext)
    max_msg_bits = msg_len * 8
    max_msg_int = pow(2, max_msg_bits) - 1

    # primes only chosen when p/q not preset which can cause problems with small messages
    # recommended key size is 2 x message length p/q == m ensures n == m^2 length
    # can use math.sqrt as optimization at the expense of adding a float ceiling
    MIN_PRIME = max_msg_int
    MAX_PRIME = MIN_PRIME * 2
    
    #---------------------------------

    n, e, d, phi = generate_exponents(p, q, e)
    encoded_message, encoded_hash = encode_string(original_plaintext, hash=hash, 
                                               payload=payload, encoding=encoding)

    # If message length exceeds key length the cipher will wrap around
    # and start repeating itself (this is due to the cyclic nature of the 
    # multiplicative group of integers modulo n) - in practice this will 
    # effectively truncate the data at the key length, corrupting it
    if encoded_message.bit_length() >= n.bit_length():
        raise RuntimeError("Message length >= encryption key length")
    
    hashing = True
    if n.bit_length() < 256:
        print("Warning: n is too small to cover the sha-256 hash so hashing results will be omitted/ignored")
        hashing = False

    encrypted_message = encrypt_message(encoded_message, n, e)
    encrypted_hash = encrypt_hash(encoded_hash, n, d)

    #---------------------------------

    decrypted_message = decrypt_message(encrypted_message, n, d)
    decrypted_hash = decrypt_hash(encrypted_hash, n, e)
    decoded_plaintext, payload_hash = decode_string(decrypted_message, hash=hash, 
                                                    payload=payload, encoding=encoding)
    decoded_hash = decode_hash(decrypted_hash)

    #---------------------------------
    
    print(f"p: {p}")
    print(f"q: {q}")
    print(f"n: {n}, bit_length: {n.bit_length()}")
    print(f"phi: {phi}")
    print(f"e: {e}")
    print(f"d: {d}")

    print("=====================")

    if payload is None:
        print(f"original_plaintext: {original_plaintext}, length: {len(original_plaintext)}")

    print(f"encoded_message: {encoded_message}, bit_length: {max_msg_int.bit_length()}")
    print(f"encrypted_message: {encrypted_message}, bit_length: {encrypted_message.bit_length()}")

    if hashing:
        print(f"encoded_hash: {encoded_hash}, bit_length: {encoded_hash.bit_length()}")
        print(f"encrypted_hash: {encrypted_hash}, bit_length: {encrypted_hash.bit_length()}")

    print("=====================")

    print(f"decrypted_message: {decrypted_message}, bit_length: {max_msg_int.bit_length()}")
    print(f"decoded_plaintext: {decoded_plaintext}, length: {len(decoded_plaintext)}")

    if hashing:
        print(f"decrypted_hash: {decrypted_hash}, bit_length: {decrypted_hash.bit_length()}")
        print(f"payload_hash: {payload_hash.hex()}, length: {len(payload_hash)*2} // 2 x hex chars per byte")
        print(f"decoded_hash: {decoded_hash.hex()}, length: {len(decoded_hash)*2} // 2 x hex chars per byte")
    
    print("=====================")
    
    print("encrypt_messages / sec:", int(1 / timeit.timeit(lambda: encrypt_message(encoded_message, n, e), number=1)))       
    print("decrypt_messages / sec:", int(1 / timeit.timeit(lambda: decrypt_message(encrypted_message, n, d), number=1)))

    if hashing:
        print("sha-256 hashes / sec:", int(1 / timeit.timeit(lambda: hashlib.sha256(original_plaintext.encode(encoding)).digest(), number=1)))
        print("encrypt_hashes / sec:", int(1 / timeit.timeit(lambda: encrypt_hash(encoded_hash, n, d), number=1)))
        print("decrypt_hashes / sec:", int(1 / timeit.timeit(lambda: decrypt_hash(encrypted_hash, n, e), number=1)))

    # debug tests that assume access to both exponents / ends of transmission

    # validate end-to-end encryption / decryption of text
    if payload is None:
        assert original_plaintext == decoded_plaintext
    else:
        assert payload == decoded_plaintext

    # validate the integrity of the hashes
    if hashing:
        assert payload_hash == decoded_hash
        assert encoded_hash == decrypted_hash
        assert hashlib.sha256(original_plaintext.encode(encoding)).digest() == \
            hashlib.sha256(decoded_plaintext.encode(encoding)).digest()

    # compare the original + decrypted results (still encoded as int)
    # also validate the proof that its a product of both exponents
    assert encoded_message == decrypted_message == pow(encoded_message, e*d, n)
    if hashing:
        assert encoded_hash == decrypted_hash == pow(encoded_hash, e*d, n)

    # validate message & hash were encrypted
    assert encoded_message != encrypted_message
    if hashing:
        assert encoded_hash != encrypted_hash
