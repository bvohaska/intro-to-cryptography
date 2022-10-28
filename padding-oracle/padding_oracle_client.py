import requests
from typing import Tuple
from validators import url as check_url


# Local imports
import padding_oracle


#
# HW 2b
#
HW2b_IV = bytearray.fromhex("26d1634eca6a0222fcff1f6d7bc87ddd")
HW2b_CIPHERTEXT = bytearray.fromhex("d6c88784f890d6a24c5bf2f090c0aec7151c970066589f850df329ca127e031f638cbb004c563a6617c7b2fb09f17fc7")
HW2b_URL = "https://ineedrandom.com/paddingoracle"


class PaddingAttacker():

    
    def __init__(self, 
        iv:bytearray = HW2b_IV, 
        ciphertext:bytearray = HW2b_CIPHERTEXT, 
        url:str = HW2b_URL,
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
        self.iv = iv if type(iv) == bytearray \
            else \
                bytearray(iv) if type(iv) == bytes \
            else None
        self.ciphertext = ciphertext if type(ciphertext) == bytearray \
            else \
                bytearray(ciphertext) if type(ciphertext) == bytes \
            else None
        
        assert self.url != None, "URL not a valid url format"
        assert self.iv != None, f"IV should be a bytearray or bytes. Received: {type(iv)} type"
        assert self.ciphertext != None, f"Ciphertext should be a bytearray or bytes. Received: {type(ciphertext)}"

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


    def access_decryption_oracle(self, iv: bytes, ciphertext:bytes, local:bool = None, debug:bool = False) -> str:
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
            return padding_oracle.decrypt(hex_iv=iv.hex(),hex_ct=ciphertext.hex(), debug=False)

        payload = self.create_post_payload(iv.hex(), ciphertext.hex())
    
        resp = requests.post(
            url=self.url,
            json=payload
        )

        if debug:
            print(f"Web Response - Type: {type(resp.text)}\n Data: {resp.text}")

        return resp.text.strip('\"')


def block_party(block1:bytearray, block2:bytearray, attacker:PaddingAttacker, debug:bool = False):
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

    # ******************************************************************
    #
    # [YOUR CODE HERE]
    #
    # You can use attacker.access_decryption_oracle() to reach out to the 
    # server and test if you have valid padding
    #
    # ******************************************************************
    
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

    # In reverse (last block first), go through each block and and attempt to decrypt
    #
    #   [YOUR CODE HERE]
    #
    # You can use block_party() as a function to decrypt each block

    # The last ciphertext block will use the IV so we treat this case sperately
    #
    #   [YOUR CODE HERE]
    #
    # You can use block_party() as a function to decrypt each block

    return attacker.plaintext, attacker.prf_bytes


if __name__ == "__main__":

    attacker = PaddingAttacker(
        iv = HW2b_IV,
        ciphertext = HW2b_CIPHERTEXT,
        url = HW2b_URL
    )

    # Run the padding oracle attack against a local padding oracle (for testing your code quickly)
    pt, prf = hack_gibson(attacker)

    print(f"Plaintext: {bytes(attacker.plaintext).decode('ascii')}")
    print(f"Total number of queries to the decryption oracle: {attacker.count}")

    # Run the padding oracle attack on the server
    attacker.local = False
    pt, prf = hack_gibson(attacker,debug=True)
    print(f"Plaintext: {bytes(attacker.plaintext).decode('ascii')}")
    print(f"Total number of queries to the decryption oracle: {attacker.count}")