from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from typing import Tuple

KEY = bytes.fromhex('9a1d33c0d9433f9faa77249fd19dd7fa678e41fb99617e1d782a975311b17770')
IV = bytes.fromhex('26d1634eca6a0222fcff1f6d7bc87ddd')
BLOCK_SIZE_BYTES = 16


def encrypt(
    key: bytes = KEY, 
    iv: bytes = IV, 
    blocksize_bytes: int = BLOCK_SIZE_BYTES,
    debug: bool = False) -> Tuple[str, str]:
    """Encrypts a message using AES256-CBC mode with PKCS7 padding

    Returns:
        tuple {hex}: iv and the encrypted message
    """
    plain_text = b'Came whiffling through the tulgey wood,'

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

    pass