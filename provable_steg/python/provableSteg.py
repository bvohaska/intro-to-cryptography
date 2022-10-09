"""
"""
from bitarray import bitarray
from math import ceil
import stegLibrary as steg


def decodeSteg(key: bytes,
    ciphertext_list: list[bytes],
    terminator: str,
    bits_per_message: int = 1,
    hiddentext_encoding: str = None,
    cipher_mode: str = 'CTR',
    debug: str = False) -> str:
    """Recover a hiddentext from a set of ciphertexts (messages drawn from the oracle)

    Args:
        key (bytes): shared steg key
        ciphertext_list (list): a list of ciphertexts containing stegotext
        terminator (str): a string signifying EOM
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        text_encoding (str, optional): Text encoding of the hiddentext. Defaults to None which implies bytes.
        debug (str, optional): Debug mode. Defaults to False.

    Returns:
        str: hiddentext
    """
    encrypted_message = []
    for ciphertext in ciphertext_list:
        if hiddentext_encoding != None:
            ciphertext = ciphertext.encode(hiddentext_encoding)
        encrypted_message.extend(steg.stegPRF(key, bits_per_message, ciphertext))

    encrypted_message = bitarray(encrypted_message)

    if debug:
        print(f"In decodeSteg - Received Encrypted Mesage (hex): {encrypted_message.tobytes().hex()}")

    # decrypt
    hiddentext = steg.decryptMessage(key, encrypted_message.tobytes(), cipher_mode=cipher_mode)
    if hiddentext_encoding != None:
        readable_text = hiddentext.decode(hiddentext_encoding)

    if terminator == "":
        return readable_text

    if hiddentext_encoding == None:
        terminator = terminator.encode(hiddentext_encoding)

    # TODO: BUG - there is a bug here where the end of the terminator 
    # string is found and removed but not the beginning. This may have
    # to do with python enforcing byte boundaries around the hiddentext 
    # messages that may have: BLOCK_SIZE_BITS mod 8 != 0. Tests show that
    # Python will pad the partial byte with data (maybe random-ish?). Since
    # this only affects our last byte we may concentrate a bug fix on that
    # final byte. (Or use a language with better bit manipulation :-/)
    # UPDATE: This is a bit/byte boundary issue. Python has trouble with strings
    # that have less than 8 bits per byte. This is a problem when decoding with
    # GCM and using bits/message that is not divisable by 8
    readable_text = readable_text[:readable_text.find(terminator)]
    
    return readable_text


def encodeSteg(
    key: bytes, 
    hiddentext: str, 
    terminator: str, 
    oracle: steg.Dumb_Oracle,
    bits_per_message: int = 1,
    ciphertext_encoding: str = None,
    cipher_mode: str = 'CTR',
    debug: bool = False) -> list:
    """Encode a hiddentext into a set of ciphertexts

    Args:
        key (bytes): shared steg key
        hiddentext (str): The hiddentext to be encoded
        terminator (str): a string signifying EOM
        oracle (steg.Dumb_Oracle): An oracle that draws messages from a channel
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        ciphertext_encoding (str, optional): The text encoding for the ciphertext 
            output. Defaults to None which implies the output will be bytes.
        debug (str, optional): Debug mode. Defaults to False.
        
    Returns:
        list: A list of ciphertexts messages with stegotext in them
    """
    enc_message_bytes = steg.encryptMessage(key, (hiddentext+terminator).encode('utf-8'), cipher_mode=cipher_mode)
    ciphertext_bits = steg.messageToBitArray(enc_message_bytes)
    number_of_blocks_to_encode = 8*len(enc_message_bytes)/bits_per_message
    
    if debug:
        print("In encodeSteg")
        print(f"\tEncrypted Message (hex): {enc_message_bytes.hex()}")
        print(f"\tThe number of ciphertext bits: {len(ciphertext_bits)}")
    print(f"\tNumber of {bits_per_message}-bit blocks to encode: {number_of_blocks_to_encode}")

    # Convert the ciphertext bits into several x-bit blocks
    ciphertext_bits = steg.splitBitArrayIntoChunks(ciphertext_bits, bits_per_message, debug)

    output_ciphertexts = []
    for index, target_bits in enumerate(ciphertext_bits):

        # Find messages drawn from a channel that PRF to our target bit (1 tweet / ciphertext_bits)
        ciphertext = rejectionSampler(key, bitarray(list(target_bits)), oracle, bits_per_message,ciphertext_encoding, debug)
        output_ciphertexts.append(ciphertext)

        print(f"\tCompleted Block {index+1} of {number_of_blocks_to_encode}")
        if debug:
            print(f"\t\tIndex: {index}")
            print(f"\t\tData type of ciphertext: {type(ciphertext)}")
        
    return output_ciphertexts


def rejectionSampler(key: bytes, 
    target_bits: bitarray, 
    oracle: steg.Dumb_Oracle,
    bits_per_message: int = 1,
    text_encoding: str = None,
    debug: bool = False) -> str:
    """_summary_

    Args:
        key (bytes): shared steg key
        target_bits (bitarray): a bitarray that the PRF output should match
        oracle (steg.Dumb_Oracle): An oracle that draws messages from a channel
        bits_per_message (int, optional): Number of bits per message. Defaults to 1.
        text_encoding (str, optional): The text encoding for the ciphertext output. 
            Defaults to None which implies the output will be bytes.
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
        length_difference = len(trial_bits) - len(target_bits)
        if True:
            print(f"\tSize Trial: {len(trial_bits)}")
            print(f"\tSize Target: {len(target_bits)}")
            print(f"\tDifference in size: {length_difference}")
        if  length_difference < bits_per_message:
            target_bits += length_difference*bitarray('0')
            print(f"\tNew Size Target: {len(target_bits)}")
        else:
            raise ValueError(f"Target and Trial not of equal length.") \
    
    while trial_bits != target_bits:
        trial_ciphertext = oracle.draw_from_channel()
        trial_bits = steg.stegPRF(key, bits_per_message, trial_ciphertext)

        if debug:
            print(f"Target bit: {target_bits}, Calculated Bit: {trial_bits}, Ciphertext: {trial_ciphertext}")
    
    # return ciphertext that makes this work
    if text_encoding == None:
        return trial_ciphertext

    return trial_ciphertext.decode(text_encoding)


def test_encode_decode_regression():

    hiddentext = "Attack at dawn"
    terminator = "000"
    bits_per_message = 8

    key = bytes.fromhex('de61390bf6b82420359c9eb4d8d82882762f0514503b72ec469503aba97fd0cf')
    oracle = steg.Dumb_Oracle()
    oracle.load_tweets()

    ciphertexts = encodeSteg(key, hiddentext, terminator, oracle, bits_per_message, 'utf-8')
    decoded_message = decodeSteg(key, ciphertexts, "000", bits_per_message, 'utf-8')

    assert decoded_message == hiddentext
    

if __name__ == "__main__":

    # Set a hiddentext message that we want to encode in a set of tweets
    hiddentext = "Attack at dawn"

    # Set a terminator that we will use to show the end of the message (not strictly necessary)
    terminator = ""

    path = 'cipherTweets.json'

    # Load or create a key that we will use for steg
    key = bytes.fromhex('de61390bf6b82420359c9eb4d8d82882762f0514503b72ec469503aba97fd0cf')
    block_mode = 'GCM'

    # Set the number of bits of hiddentext to be encoded in a message
    bits_per_message = 8

    # Our message channel is the set of elon musk tweets. Load these tweets into our dumb oracle
    oracle = steg.Dumb_Oracle()
    oracle.load_tweets(path='elonmusk_tweets_big.json')
    print(f"The number of tweets currently loaded is: {len(oracle.history)}")

    # Encode the hiddentext into a channel message. We don't timestamp these and our 
    # oracle is dumb so this isn't stricly secure.
    ciphertexts = encodeSteg(
        key, 
        hiddentext, 
        terminator, 
        oracle, 
        bits_per_message, 
        'utf-8', 
        block_mode, 
        debug=False
    )

    print(f"Number of ciphertexts needed to send the hiddentext: {len(ciphertexts)}")

    # Recover the hiddentext from the set of ciphertext messages
    decoded_message = decodeSteg(
        key, 
        ciphertexts, 
        terminator, 
        bits_per_message, 
        'utf-8', 
        block_mode, 
        debug=True
    )

    print(f"Recovered hiddentext: {decoded_message}")

    # Save the ciphertexts as a set of messages in JSON format
    if len(path) > 0:
        from json import dumps
        print(f"Saving ciphertexts: {path}")
        with open(path,'w') as cipherTweets:
            cipherTweets.write(dumps(ciphertexts))


    
