"""
"""
import stegLibrary as steg
from bitarray import bitarray


def decodeSteg(key: bytes,
    ciphertext_list: list,
    terminator: str,
    bits_per_message: int = 1,
    text_encoding: str = 'ascii',
    debug: str = False) -> str:
    """Recover a hiddentext from a set of ciphertexts (messages drawn from the oracle)

    Args:
        key (bytes): shared steg key
        ciphertext_list (list): a list of ciphertexts containing stegotext
        terminator (str): a string signifying EOM
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        text_encoding (str, optional): Text encoding of the hiddentext. Defaults to 'ascii'.
        debug (str, optional): Debug mode. Defaults to False.

    Returns:
        str: hiddentext
    """
    message = []
    for ciphertext in ciphertext_list:
        message.extend(steg.stegPRF(key, bits_per_message, ciphertext))

    message = bitarray(message)

    # decrypt
    hiddentext = steg.decryptMessage(key, message.tobytes())
    
    return hiddentext[:hiddentext.find(terminator.encode(text_encoding))]


def encodeSteg(
    key: bytes, 
    hiddentext: str, 
    terminator: str, 
    oracle: steg.Dumb_Oracle,
    bits_per_message: int = 1,
    debug: bool = False) -> list:
    """Encode a hiddentext into a set of ciphertexts

    Args:
        key (bytes): shared steg key
        hiddentext (str): The hiddentext to be encoded
        terminator (str): a string signifying EOM
        oracle (steg.Dumb_Oracle): An oracle that draws messages from a channel
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        debug (str, optional): Debug mode. Defaults to False.
        
    Returns:
        list: A list of ciphertexts messages with stegotext in them
    """
    output_ciphertexts = []

    # terminator (str): a terminator to signal the EOM
    enc_message_bytes = steg.encryptMessage(key, hiddentext + terminator)
    ciphertext_bits = steg.messageToBitArray(enc_message_bytes)

    ciphertext_bits = zip(*(iter(ciphertext_bits),) * bits_per_message)

    for index, target_bits in enumerate(ciphertext_bits):

        # Find tweets that PRF to our target bit (1 tweet / bit)
        output_ciphertexts.append(rejectionSampler(key, bitarray(list(target_bits)), oracle, bits_per_message))

        if debug:
            print(f"Index: {index}")

    return output_ciphertexts


def rejectionSampler(key: bytes, 
    target_bits: bitarray, 
    oracle: steg.Dumb_Oracle,
    bits_per_message: int = 1,
    debug: bool = False) -> str:
    """_summary_

    Args:
        key (bytes): shared steg key
        target_bits (bitarray): a bitarray that the PRF output should match
        oracle (steg.Dumb_Oracle): An oracle that draws messages from a channel
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        debug (str, optional): Debug mode. Defaults to False.

    Raises:
        TypeError: Error if trial and targets bits are not the same type
        ValueError: Error if trial and targets bits are not the same length

    Returns:
        str: A ciphertext that has encoded bits_per_message bits of a hiddentext
    """
    trial_ciphertext = oracle.draw_from_channel()
    trial_bits = steg.stegPRF(key, bits_per_message, trial_ciphertext)

    if type(trial_bits) != type(target_bits):
        raise TypeError(f"Target {type(target_bits)} and Trial {type(trial_bits)} not of same type")
    if len(trial_bits) != len(target_bits):
        raise ValueError("Target and Trial not of equal length")
    
    while trial_bits != target_bits:
        trial_ciphertext = oracle.draw_from_channel()
        trial_bits = steg.stegPRF(key, bits_per_message, trial_ciphertext)

        if debug:
            print(f"Target bit: {target_bits}, Calculated Bit: {trial_bits}, Ciphertext: {trial_ciphertext}")
    
    # return ciphertext that makes this work
    return trial_ciphertext


def test_encode_decode_regression():

    hiddentext = "Attack at dawn"
    terminator = "000"
    bits_per_message = 2

    key = bytes.fromhex('de61390bf6b82420359c9eb4d8d82882762f0514503b72ec469503aba97fd0cf')
    oracle = steg.Dumb_Oracle()
    oracle.load_tweets()

    ciphertexts = encodeSteg(key, hiddentext, terminator, oracle, bits_per_message)
    decoded_message = decodeSteg(key, ciphertexts, "000", bits_per_message)

    assert decoded_message.decode('ascii') == hiddentext
    

if __name__ == "__main__":

    key = bytes.fromhex('de61390bf6b82420359c9eb4d8d82882762f0514503b72ec469503aba97fd0cf')
    oracle = steg.Dumb_Oracle()
    oracle.load_tweets()
    bits_per_message = 8

    ciphertexts = encodeSteg(key, "Attack at dawn", "000", oracle, bits_per_message)

    print(f"Number of ciphertexts needed to send the hiddentext: {len(ciphertexts)}")

    decoded_message = decodeSteg(key, ciphertexts, "000", bits_per_message)

    print(f"Recovered hiddentext: {decoded_message.decode('ascii')}")

    
