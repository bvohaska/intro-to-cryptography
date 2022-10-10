from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

KEY = bytes.fromhex('9a1d33c0d9433f9faa77249fd19dd7fa678e41fb99617e1d782a975311b17770')
IV = bytes.fromhex('26d1634eca6a0222fcff1f6d7bc87ddd')
BLOCK_SIZE = 16

def encrypt():
    """Encrypts a message using AES256-CBC mode with PKCS7 padding

    Returns:
        bytes: padded and encrypted message
    """
    plain_text = b'SomethingSomethingSomethingSomethingSomething'
    enc_cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_plain_text = pad(plain_text, BLOCK_SIZE)
    cipher_text = enc_cipher.encrypt(padded_plain_text)
    return (IV.hex(), cipher_text.hex())

def decrypt(h_iv, h_ct):
    """Decrypts the provided hex string and returns whether or not
    the padding is valid

    Args:
        cipher_text {bytes}: the hex string to be decrypted

    Returns:
        String: Valid or Invalid
    """
    cipher_text = bytes.fromhex(h_ct)
    iv = bytes.fromhex(h_iv)
    dec_cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded_plain_text = dec_cipher.decrypt(cipher_text)
    if not valid_padding(padded_plain_text):
        return "Invalid Padding"
    #plain_text = unpad(padded_plain_text, BLOCK_SIZE)
    return "Valid"

def valid_padding(padded_plain_text):
    """Checks for valid PKCS7 padding

    Args:
        padded_plain_text (bytes): the decrypted plain text

    Returns:
        Bool: true if it is a valid pad, false otherwise
    """
    #get last byte of plain text
    pad_size = padded_plain_text[-1]
    if (pad_size < 1 or pad_size > 16):
        return False
    #check that pad_size number of bytes are equal to pad_size
    padding = padded_plain_text[len(padded_plain_text) - pad_size:]
    for i in padding:
        if i != pad_size:
            return False
    return True
