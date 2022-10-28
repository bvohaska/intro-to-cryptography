import padding_oracle_client as poc
from typing import Tuple


def block_party(block1:bytearray, block2:bytearray, attacker:poc.PaddingAttacker, debug:bool = False):
    """The heavy lifting of the padding attack.

    Attempt to decrypt only 1 CBC block. Recall,

        CBC Decrypt ->

                PRF_k( [N-th block cipehrtext] )
                
                    XOR 
                
                [(N-1)th-Block]

                    =

                [Plain Text]

    Picture: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:CBC_decryption.svg
    
    Args:
        block1 (bytearray): A set of bytes representing the "IV" for the decryption 
            block. This block will change as we attempt to find the correct padding 
            bytes.
        block2 (bytearray): The ciphertext block (16 bytes) that we will feed into the 
            PRF. This is something we can't change in the attack.
        attacker (PaddingAttacker): Our padding attacker class that stores some useful 
            information
        debug (bool, optional): Print all the things when debugging. Defaults to False.

    Returns:
        Tuple[bytearray, bytearray]: The PRF bytes and Plaintext bytes resulting from 
            attacking the oracle for this cipherblock.
    """
    prf_bytes = bytearray([0]*len(block2))
    plaintext_bytes = bytearray([0]*len(block2))

    trial_iv = block1.copy()
    for byte in range(1,17):

        if debug:
            print(f"On byte: {byte}")
        
        # If we know the output bytes of the PRF, go back and 
        # set the trial_iv bytes so that the PRF bytes XOR iv 
        # gives us the correct padding byte. 
        # 
        #   trial_iv_byte = PRF_byte XOR target_padding_Value
        #
        # his works b/c we know,
        #
        #   plaintext_byte = trial_iv_byte XOR PRF_byte (<-- this is what the oracle sees)   
        #                  = PRF_byte XOR target_padding_value XOR PRF_byte
        #                  = target_padding_value (<-- we want this to be something we know)
        #
        # This will only run after we have determined the first 
        # byte of PRF output.
        for j in range(byte):
                trial_iv[-j] = prf_bytes[-j]^byte
        
        # Try every value for our trial byte until we get a 
        # padding validation confirmation from the decryption 
        # oracle. If we succeed, infer/derive the values of 
        # the plaintext and PRF bytes (which we can know b/c we
        # have presumably started from the single padding byte 
        # and worked our way though the block until we reach 16
        # padding bytes).
        for i in range(0,256):
            attacker.count += 1
            trial_iv[-byte] = i
            isValid = attacker.access_decryption_oracle(trial_iv, block2)
            if isValid == "Valid":
                prf_byte = trial_iv[-byte]^byte
                plaintext_byte = prf_byte^block1[-byte]
                prf_bytes[-byte] = prf_byte
                plaintext_bytes[-byte] = plaintext_byte
                if debug:
                    print(f"PRF Byte: {prf_byte}")
                    print(f"PT Byte: {chr(plaintext_byte)}")
                    print(f"Modified IV ({i} steps): {trial_iv}")
                    print(f"{byte}-th IV byte: {trial_iv[-byte]}")
                    print(f"Attacker PRF Byte: {prf_bytes[-byte]}")
                    print(f"Attacker PT Byte: {plaintext_bytes[-byte]}")
                break
        if debug:
            print(f"Plaintext bytes so far: {plaintext_bytes}")
    
    return prf_bytes, plaintext_bytes


def hack_gibson(
    attacker: poc.PaddingAttacker, 
    iv: bytearray = None,
    ciphertext: bytearray = None,
    block_size_bytes:int = 16,
    debug: bool = False
) -> Tuple[bytearray, bytearray]:
    """Hold on to your butts.

    Defeat the padding oracle and decrypt the ciphertext without 
    the key used for encryption. We assume that the ciphertext
    was encrypted using CBC mode for some CCA-insecure cipher
    which implies the decryption oracle does not use authenticated
    encryption. Of, if it does, the authenticated encryption 
    mechanism allows for MAC attacks.

    Args:
        attacker (PaddingAttacker): A padding attacker class to hold 
            some useful information.
        iv (bytearray, optional): IV of for the ciphertext. Defaults to None.
        ciphertext (bytearray, optional): Ciphertext we wish to decrypt. 
            Defaults to None.
        block_size_bytes (int, optional): the size of the cipher block. 
            Defaults to 16.
        debug (bool, optional): Debug output in the form of a boat-load of 
            print statements. Should move to logging and log levels. You 
            are encouraged to make a pull request. Defaults to False.

    Returns:
        Tuple[bytearray, bytearray]: returns the plaintext and associated PRF bytes
    """
    if iv != None:
        attacker.iv = iv
    if ciphertext != None:
        attacker.ciphertext = ciphertext

    ciphertext_blocks = attacker.split_ciphertext_into_blocks(attacker.ciphertext, block_size_bytes)
    if debug:
        print(f"The size of the ciphertext: {len(attacker.ciphertext)}")

    # In reverse (last block first), go through each block and and attempt to decrypt
    for block in range(len(ciphertext_blocks)-1,0, -1):
        prf, pt = block_party(ciphertext_blocks[block-1], ciphertext_blocks[block], attacker, debug)
        attacker.plaintext[(block)*16:(block+1)*16] = pt
        attacker.prf_bytes[(block)*16:(block+1)*16] = prf

    # The last ciphertext block will use the IV so we treat this case sperately
    prf, pt = block_party(attacker.iv, ciphertext_blocks[0], attacker, debug)
    attacker.plaintext[:16] = pt
    attacker.prf_bytes[:16] = prf

    return attacker.plaintext, attacker.prf_bytes


if __name__ == "__main__":

    attacker = poc.PaddingAttacker()

    # Run the padding oracle attack against a local padding oracle (for testing your code)
    print("Running LOCAL Padding Oracle Attack...")
    pt, prf = hack_gibson(attacker)
    print("Completed LOCAL Padding Oracle Attack!")

    print(f"Recovered Plaintext: {bytes(attacker.plaintext).decode('ascii')}")
    print(f"Total number of queries to the decryption oracle: {attacker.count}")

    # Run the padding oracle attack on the server
    attacker.local = False
    print("Running REMOTE Padding Oracle Attack. This might take a while...")
    pt, prf = hack_gibson(attacker,debug=False)
    print("Completed REMOTE Padding Oracle Attack!")
    print(f"Plaintext: {bytes(attacker.plaintext).decode('ascii')}")
    print(f"Total number of queries to the decryption oracle: {attacker.count}")