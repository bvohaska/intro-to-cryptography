import requests
from typing import Tuple
from validators import url as check_url


#
# HW 2b
#
HW2b_IV = bytearray.fromhex("26d1634eca6a0222fcff1f6d7bc87ddd")
HW2b_CIPHERTEXT = bytearray.fromhex("d6c88784f890d6a24c5bf2f090c0aec7151c970066589f850df329ca127e031f638cbb004c563a6617c7b2fb09f17fc7")

class PaddingAttacker():

    
    def __init__(self, 
        iv:bytearray = HW2b_IV, 
        ciphertext:bytearray = HW2b_CIPHERTEXT, 
        url:str = "https://ineedrandom.com/padingoracle",
        local:bool = True
    ) -> None:
        """Initialize a padding attacker

        Args:
            iv (bytes): The bytes of an IV. Defaults to HW2b_IV.
            ciphertext (bytearray): A bytearray containing the starting ciphertext. Defaults to HW2b_IV.
            url (str, optional): URL of the Decryption Oracle. Defaults 
                to "https://ineedrandom.com/padingoracle".
            local (bool, optional): If true, runs the attack locally. Defaults to True.

        Raises:
            TypeError: Received URL was not a valid URL
            TypeError: IV was not the bytes type
            TypeError: Ciphertext was not a bytearray or of type bytes

        Returns:
            None: Init success
        """
        # Do some type checking and input validation
        self.url = url if check_url(url) else None
        if self.url == None:
            raise TypeError("URL not a valid url format")
        self.iv = iv if type(iv) == bytearray \
            else \
                bytearray(iv) if type(iv) == bytes \
            else None
        if self.iv == None:
            raise TypeError(f"IV should be a bytearray or bytes. Received: {type(iv)} type")
        self.ciphertext = ciphertext if type(ciphertext) == bytearray \
            else \
                bytearray(ciphertext) if type(ciphertext) == bytes \
            else None
        if self.ciphertext == None:
            raise TypeError(f"Ciphertext should be a bytearray or bytes. Received: {type(ciphertext)}")

        # Build byte arrays to hold PRF and Plaintext values that we find though the attack
        self.prf_bytes = bytearray([0] * len(ciphertext))
        self.plaintext = bytearray([0] * len(ciphertext))

        # Set local decryption for testing
        self.local = local

        # Set total number of queries to decrypt the ciphertext
        self.count = 0

        return None

    
    def create_post_payload(self, iv:str = None, ciphertext:str = None) -> dict:
        """Create a dictionary that will be used as the POST request body

        Args:
            iv (str, optional): Hex encoded string of IV bytes. Defaults to None.
            ciphertext (str, optional): Hash encoded string of ciphertext bytes. Defaults to None.

        Returns:
            dict: The POST request payload with hex string values
        """
        payload = {
            "iv": iv,
            "ciphertext": ciphertext
        }

        return payload


    def split_ciphertext_into_blocks(self,ciphertext:bytearray, block_size_bytes:int = 16) -> list:
        """Split a ciphertext into chunks of size len(block_size_bytes)

        Args:
            ciphertext (bytearray): A bytearray containing the original ciphertext
            block_size_bytes (int, optional): The size of the cipher block. AES is 
                16 bytes (128 buts). Defaults to 16.

        Raises:
            ValueError: Error for when the received ciphertext was not padded correctly

        Returns:
            list: A list of bytearrays each containing a block of ciphertext
        """
        if len(ciphertext) % block_size_bytes != 0:
            raise ValueError("Ciphertext is not a multiple of block size!")

        blocks = []
        for index in range(0,len(ciphertext), block_size_bytes):
            blocks.append(ciphertext[index:index+block_size_bytes])

        return blocks


    def access_decryption_oracle(self, iv: bytes, ciphertext:bytes, local:bool = None) -> str:
        """Create a communication interface for the decryption oracle

        Args:
            iv (bytes): the trial IV for the ciphertext
            ciphertext (bytes): the ciphertext
            local (bool, optional): If set to True, run the attack 
                against a local oracle; great for testing. Defaults to None.

        Returns:
            str: the text of the POST request which should be a simple string
        """
        if local == None and self.local == True:
            import padding_oracle
            return padding_oracle.decrypt(hex_iv=iv.hex(),hex_ct=ciphertext.hex(), debug=False)

        payload = self.create_post_payload(iv.hex(), ciphertext.hex())
    
        resp = requests.post(
            url=self.url,
            json=payload
        )

        return resp.text


def block_party(block1:bytearray, block2:bytearray, attacker:PaddingAttacker, debug:bool = False):
    """The heavy lifting of the padding attack.

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
    
    return prf_bytes, plaintext_bytes


def hack_gibson(
    attacker: PaddingAttacker, 
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

    for block in range(len(ciphertext_blocks)-1,0, -1):
        prf, pt = block_party(ciphertext_blocks[block-1], ciphertext_blocks[block], attacker)
        attacker.plaintext[(block)*16:(block+1)*16] = pt
        attacker.prf_bytes[(block)*16:(block+1)*16] = prf

    prf, pt = block_party(attacker.iv, ciphertext_blocks[0], attacker)
    attacker.plaintext[:16] = pt
    attacker.prf_bytes[:16] = prf

    return attacker.plaintext, attacker.prf_bytes


if __name__ == "__main__":

    attacker = PaddingAttacker()

    pt, prf = hack_gibson(attacker)

    print(f"Plaintext: {bytes(attacker.plaintext).decode('ascii')}")
    print(f"Total number of queries to the decryption oracle: {attacker.count}")
    