from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv
import os
from typing import Tuple


BLOCK_SIZE_BYTES = 16


load_dotenv('secrets.env')
REQUIRED_ENV_VARIABLES = set(['KEY','IV','PLAINTEXT'])
SYSTEM_ENV_VARIABLES = set(os.environ)
if len(REQUIRED_ENV_VARIABLES - SYSTEM_ENV_VARIABLES) == 0:
    KEY = bytes.fromhex(os.environ.get('KEY'))
    IV = bytes.fromhex(os.environ.get('IV'))
    PLAINTEXT = os.environ.get('PLAINTEXT').encode('utf-8')
else:
    KEY = os.urandom(32)
    IV = os.urandom(16)
    PLAINTEXT = b'I am the wrong answer. You see something else here'


def encrypt(
    key: bytes = KEY, 
    iv: bytes = IV, 
    blocksize_bytes: int = BLOCK_SIZE_BYTES,
    plain_text = PLAINTEXT,
    debug: bool = False) -> Tuple[str, str]:
    """Encrypts a message using AES256-CBC mode with PKCS7 padding

    Returns:
        tuple {hex}: iv and the encrypted message
    """
    
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(8*blocksize_bytes).padder()
    padded_plain_text = padder.update(plain_text) 
    padded_plain_text += padder.finalize()
    if debug:
        print(f"Padded Plaintext: {padded_plain_text}")
        print(f"Plaintext Length: {len(plain_text)}")
        print(f"Padded Plaintext Length: {len(padded_plain_text)}")

    ciphertext = encryptor.update(padded_plain_text) + encryptor.finalize()
    
    return (iv.hex(), ciphertext.hex())


def test_encrypt():
    plaintext = b'I am the monarch of the sea...'
    iv = bytes.fromhex('46cf47c87ec3af50d898af6a98198b10')
    key = bytes.fromhex('d66a7013c22584a1e09e0ab63c8c76d414f1863c50334da499a71d0c0f041eed')

    iv_hex, ciphertext_hex = encrypt(key, iv, BLOCK_SIZE_BYTES, plaintext)

    assert ciphertext_hex == 'ef9dfc4086651bfdc418d9d10d2d5d4e01c26d64099a584b88e9b82f7d1a379a', \
        "ciphertext_hex is not correct"
    assert iv_hex == '46cf47c87ec3af50d898af6a98198b10', "iv_hex is not correct"


def decrypt(
    key: bytes = KEY,
    hex_iv: str = IV.hex(), 
    hex_ct: str = '',
    debug: bool = False) -> str:
    """Decrypts the provided hex string and returns whether or not
    the padding is valid

    Args:
        h_iv {hex string}: the iv as a hex string
        h_ct {hex string}: the hex string to be decrypted

    Returns:
        String: Valid or Invalid
    """
    # Convert ct and iv into bytes
    cipher_text = bytes.fromhex(hex_ct)
    iv = bytes.fromhex(hex_iv)
    if debug:
        print(f"Loaded Key: {key.hex()}")
        print(f"Loaded IV: {iv.hex()}")
        print(f"Loaded Ciphertext: {cipher_text.hex()}")

    # Decrypt to give padded plaintext
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded_plaintext = decryptor.update(cipher_text) + decryptor.finalize()
    if debug:
        print(f"Padded Plaintext: {padded_plaintext}")
    
    # Check padding
    if not valid_padding(padded_plaintext):
        return "Invalid Padding"

    return "Valid"


def test_decrypt():
    key = bytes.fromhex('d66a7013c22584a1e09e0ab63c8c76d414f1863c50334da499a71d0c0f041eed')    
    ciphertext_hex = 'ef9dfc4086651bfdc418d9d10d2d5d4e01c26d64099a584b88e9b82f7d1a379a'
    iv_hex = '46cf47c87ec3af50d898af6a98198b10'

    assert decrypt(key, iv_hex, ciphertext_hex) == 'Valid', "Failed Padding Check"


def valid_padding(padded_plain_text: bytes) -> bool:
    """Checks for valid PKCS7 padding

    Args:
        padded_plain_text (bytes): the decrypted plain text

    Returns:
        Bool: true if it is a valid pad, false otherwise
    """
    # Get last byte of plain text
    pad_size = padded_plain_text[-1]
    if (pad_size < 1 or pad_size > 16):
        return False

    # Check that pad_size number of bytes are equal to pad_size
    padding = padded_plain_text[len(padded_plain_text) - pad_size:]
    for i in padding:
        if i != pad_size:
            return False
    return True


if __name__ == "__main__":

    plaintext = b'Welcome to the jungle! We\'ve got fun and games'

    iv_hex, ciphertext_hex = encrypt(
        key = KEY,
        iv = IV,
        blocksize_bytes = BLOCK_SIZE_BYTES, 
        plain_text = plaintext, 
        debug = True
    )

    result = decrypt(
        key = KEY,
        hex_iv = iv_hex, 
        hex_ct = ciphertext_hex,
        debug = True
    )
    print(f"The padding was {result}")
