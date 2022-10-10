from cryptography.hazmat.primitives import hashes
from secrets import choice, randbits
from time import sleep
from typing import Tuple

from os import urandom

debug_mode = True
sleepy_time = 10

# bvohaska: TODO: move to ci/cd variable; to students --> don't be a butthole
admin_key = '895f633e1e8dee1e5e05de35336228e4'
if debug_mode:
    server_key = bytes.fromhex('ddb1d9f8265d177a0187dc986d89b2ec')
else:
    server_key = urandom(16)

def xor(input1: bytes, input2: bytes) -> bytes:
    """XOR the content two bytes classes

    Args:
        input1 (bytes): bytes class
        input2 (bytes): bytes class

    Returns:
        bytes: The result of the XOR operation
    """
    return bytes(a ^ b for a, b in zip(input1, input2))


def split_inputs(student_input: str, debug: bool = False) -> Tuple[bytes, bytes]:
    # GET / POST to receive a input; Input must be hex
    # Input is of the form: m1||m2 and |m1| = |m2| = 128 bits
    try:
        student_input = bytes.fromhex(student_input)
        m1 = student_input[:16]
        m2 = student_input[16:]
        if debug:
            print(f"Input as Hex: {student_input.hex()}")
            print(f"m1 as Hex: {m1.hex()}")
            print(f"m2 as Hex: {m2.hex()}")
    except Exception as e:
        print(e)

    return m1, m2

def test_split_inputs():
    student_input = "cc2fea0f3ad324bb004fe52fb4e62d28b9cb0d04ec65f9033fb72748937d73b3"
    m1, m2 = split_inputs(student_input)

    assert len(m1) == len(m2)
    assert m1.hex() == "cc2fea0f3ad324bb004fe52fb4e62d28"
    assert m2.hex() == "b9cb0d04ec65f9033fb72748937d73b3"


def do_short_sha2(input: bytes) -> bytes:
    hash_fn = hashes.Hash(hashes.SHA256())

    hash_fn.update(input)

    return hash_fn.finalize()[:16]

def test_do_short_sha2():
    input_bytes = "attack at dawn".encode('ascii')

    out = do_short_sha2(input_bytes)

    assert out.hex() == 'd502810c71aeb17e5ea1cbf930b46b87'


def do_prf(key:bytes, input:bytes) -> bytes:
    # Create PRF from Keyed SHA2
    prf = hashes.Hash(hashes.SHA256())

    prf.update(key)
    prf.update(input)

    return prf.finalize()[:16]

def test_do_prf():
    key = bytes.fromhex('c802bec7efbc107b9f9742ae2cf18f98')
    input_bytes = "attack at dawn".encode('ascii')

    out = do_prf(key,input_bytes)
    assert len(out) == 16
    assert out.hex() == 'b97ee9999e7bebc4239f6912923af0b9'


def encryption_oracle(
    server_key: bytes, 
    big_message: str, 
    random_nonce: bytes = None, 
    output_hex: bool = False) -> Tuple[bytes, bytes, bytes]:
    """Given one message called m1||m2, encrypt this message
        (poorly) and return one 3-tuple representing a ciphertext

    Args:
        server_key (bytes): the server's encryption 128-bit key
        big_message (bytes): A 256-bit hex encoded string

    Returns:
        Tuple: (A random nonce, first ciphertext, second ciphertext)
    """
    if random_nonce == None:
        random_nonce = randbits(128).to_bytes(16,'little')

    m1,m2 = split_inputs(big_message)

    c1 = xor(do_prf(server_key, random_nonce), m2)
    c2 = xor(do_prf(server_key, m2), m1)

    if output_hex:
        random_nonce.hex(), c1.hex(), c2.hex()

    return random_nonce, c1, c2

def test_encryption_oracle():
    key = bytes.fromhex('c802bec7efbc107b9f9742ae2cf18f98')
    big_message = "cc2fea0f3ad324bb004fe52fb4e62d28b9cb0d04ec65f9033fb72748937d73b3"
    random_nonce = bytes.fromhex('bf28d64199ae08bb6b419e7483e965da')

    r, c1, c2 = encryption_oracle(key,big_message,random_nonce)
    assert r == random_nonce
    assert c1.hex() == "1ebb2235c52bd639b3babdda77f1d8db"
    assert c2.hex() == "67bc9c3f31c38e209936ef2b3e381a9d"


def challenge_oracle(
    server_key: bytes, 
    state_dict: dict, 
    challenge_m1:str, 
    challenge_m2:str,
    selected_challenge: int = None,
    random_nonce: bytes = None,
    output_hex = False,
    debug: bool = False) -> Tuple[bytes, bytes, bytes]:
    """Receive two messages from an adversary and encrypt only one.
        Return the output to the message creator. Sleep for 10 secs.
        to discourage spamming the server
    

    Args:
        state_list: a list of all valid ciphertexts
        challenge_m1 (bytes): 256-bit hex encoded string
        challenge_m2 (bytes): 256-bit hex encoded string

    Returns:
        bytes: Return the challenge tuple
    """

    if not debug:
        sleep(sleepy_time)

    if challenge_m1 == challenge_m2:
        raise Exception("m1 cannot equal m2")

    if selected_challenge == None:
        selected_challenge = choice([1,2])
    
    if selected_challenge == 1:
        challenge_c = encryption_oracle(server_key, challenge_m1, random_nonce=random_nonce, output_hex=output_hex)
    else:
        challenge_c = encryption_oracle(server_key, challenge_m2, random_nonce=random_nonce, output_hex=output_hex)
    
    # Save the challenge ciphertext in a list
    # TODO: in the future tie this to a student session and delete after a day
    # TODO: bug if output_hex is true then this should fail b/c hex != bytes which is what sha2 needs
    challenge_hash = do_short_sha2(challenge_c[0] + challenge_c[1] + challenge_c[2])
    state_dict[challenge_hash] = selected_challenge

    if debug:
        print(f"Selected message: {selected_challenge}")

    return challenge_c

def test_challenge_oracle():
    state_dict = {}
    key = bytes.fromhex('c802bec7efbc107b9f9742ae2cf18f98')
    random_nonce = bytes.fromhex('bf28d64199ae08bb6b419e7483e965da')
    m1 = "1d77bd56319638cb74f5deb673612a94c69d4b4c4e805ac8ee5319a7666dae95"
    m2 = "e6e1abeebdadc8461efa2b12d65a46e5beb4e9a8548b48e9ace531d2aabc4744"
    selected_challenge = 1

    expected_ciphertext = (
        bytes.fromhex('bf28d64199ae08bb6b419e7483e965da'),
        bytes.fromhex('61ed647d67ce75f2625e833582e105fd'),
        bytes.fromhex('5878f918b09e70304eb7d5472ca22a99')
    )

    state_dict_key = do_short_sha2(expected_ciphertext[0]+expected_ciphertext[1]+expected_ciphertext[2])

    computed_output = challenge_oracle(key, state_dict, m1, m2, 1, random_nonce, False, debug = True)

    assert computed_output[0] == expected_ciphertext[0]
    assert computed_output[1] == expected_ciphertext[1]
    assert computed_output[2] == expected_ciphertext[2]
    assert state_dict[state_dict_key] == 1


def check_challenge(state_dict: dict, decision_list: list, debug: bool = False) -> bool:
    """A student will submit a decision list to the CPA challenger. Validate
        that the student has a CPA advantage.

    After querying the challenge oracle with 10 sets of 2 messages (m1,m2), the
    student will receive 10 ciphertexts corresponding to an encryption of m1 or m2.
    The student will demonstrate their CPA advantage to the CPA challenger by:
        
        for each ciphertext in the set 10 ciphertext challenges
            indicate if the ciphertext is associate with m1 or m2
            if m1, indicate 1
            if m2, indicate 2

    The corresponding decision list will be of the form,

        decision_list = [ 
            ( (r1_1, c1_1, c2_1), [indication] ),
            ...,
            ( (r1_10, c1_10, c2_10), [indication] )
        ]

        where [indication] is 1 or 2

    Args:
        state_dict (dict): A dict storing the relationship of ciphertext and message
        decision_list (list): A list of tuples (ciphertext, decision) where 
            decision from {1,2} and
            ciphertext = (r (bytes), c1 (bytes), c2 (bytes))

    Returns:
        bool: If all decisions are correct, true. Else, false

    TODO: Associate the indicator with the originating message; in other words, let the 
        indicator be the message itself
    """
    if not debug:
        sleep(sleepy_time)

    for item in decision_list:
        challenge_hash = do_short_sha2(item[0][0]+item[0][1]+item[0][2])
        if challenge_hash not in state_dict:
            return False
        if state_dict[challenge_hash] == item[1]:
            continue
        else:
            return False

    return True

def test_check_challenge():
    messages = [
        ('12343eb8c1c49c0c65f55ad9aa61e53952e09694aa689d264762afa0333de00c',1), 
        ('51a09ae6452d0248707c70aaa3972130cf6a20cfadeb3d81bc206d6b30461208',1), 
        ('9f2d3f5f8c081c1630ab38b3f0ff21db625a532bb46eb87c9bbab5a9ffb7b6cf',1), 
        ('9b1556e96bc710ff25e6022979adc75fdf6964d67911257a8938a9e2d877621a',1), 
        ('2b4bee0fbdacc0afb761738cd038ad0b0124d0fbe65199e3805c0c4666070ae3',1), 
        ('990cb02377e89a33aec8fb3c448df5685bdd24562e2a35e89ea734ebf347e576',1), 
        ('b0e10c9dfe4e9847449a8da1937bc282051309c5a68af55679ce3f134cca4aec',1), 
        ('0491aec2030605ef28b33259e2b80c7dcd2dbf49c400774958cbd1a3b34ac953',1), 
        ('8c8ae83672995cb5c6df0e9738fde4a3f480269bccb99ffda212795c52a1cdcc',1), 
        ('3d4596a19fc40ca816296476394940c97923b94b36cb4138719b60d57523d911',1)
    ]

    state_dict = {}
    key = bytes.fromhex('c802bec7efbc107b9f9742ae2cf18f98')
    random_nonce = bytes.fromhex('bf28d64199ae08bb6b419e7483e965da')

    responses = []
    for item in messages:
        responses.append(
            (
                challenge_oracle(
                    key, 
                    state_dict, 
                    item[0], 
                    randbits(128).to_bytes(16,'little'), 
                    item[1], 
                    random_nonce, 
                    False,
                    debug = True,
                ), 
                item[1]
            )
        )
    
    assert check_challenge(state_dict,responses, True) == True
    