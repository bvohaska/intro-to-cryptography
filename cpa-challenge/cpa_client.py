"""

HW2a Client

The following API calls are supported:

    1. Query the oracle
    2. Query the challenger
    3. Request a decision from the decision API

You will need to figure out how to choose messages such that 
you can beat the CPA security game.

An example of the process is at the end of this file
"""
import requests
from typing import List


server_url = 'https://ineedrandom.com/'
encryption_oracle_path = 'oracle'
challenge_path = 'challenges'
decision_path = 'decision'


def isHex(hex_string:str) -> bool:
    """Check if a string is a valid hex string

    Taken from stackoverflow (cant find link)

    Args:
        hex_string (str): string we will check for hex validity

    Returns:
        bool: True if valid, False otherwise
    """
    hex_set = set('abcdefABCDEF0123456789')

    if all(character in hex_set for character in hex_string):
        return True

    return False


class Password():
    """Create a password that the CPA server will accept.

        This password is unique to each student and should not
        be shared. If you do share this password, you may not 
        receive credit for your homework.
    """
    def __init__(self, 
        password:str = '35dea77adb321f771d52673752756176'
    ) -> None:
        """Construct the class and set the password
         
        Args:
            password (str, optional): A 256-bit hex-encoded password.
                Defaults to '35dea77adb321f771d52673752756176'.

        Returns:
            None: return None
        """
        self.password = password
        
        return None
    
    @property
    def password(self) -> str:
        """Return the Password's password as a string

        Returns:
            str: the hex encoded password as a string
        """
        return self._password

    @property.setter
    def set_password(self, password:str):
        """Set the password
        
        Take a password and check that the password is of the correct length 
        and format.

        Args:
            password (str): A 256-bit hex-encoded password

        Raises:
            TypeError: The password was not the correct length (32 hex chars)
            TypeError: The password was not a valid hex string
        """
        if len(password) != 32:
            raise TypeError(f"The password should be 128 bits but received {len(password)*4} bits")
        if not isHex(password):
            raise TypeError("Password input is not a hex string")
        
        self._password = password


class Message():
    """Create a message that the CPA server will understand
    """
    def __init__(self, 
        message:str  = '6b7f198df6f89a5291f6daccdd619ed17bd9868daa359a9ee958a24bc31b7204'
    ) -> None:
        """Construct Message and set the message attribute

        Args:
            message (str, optional): The message to be sent. The message should be 
                hex encoded and must be 64 hex characters long (256-bits). Defaults 
                to '6b7f198df6f89a5291f6daccdd619ed17bd9868daa359a9ee958a24bc31b7204'.

        Returns:
            None: return None
        """
        self.message = message
        
        return None

    @property
    def message(self) -> str:
        """Get a message from the Message class

        Returns:
            str: the message attribute
        """
        return self._message

    @property.setter
    def set_message(self, message:str):
        """Sets the message and checks for errors

        Args:
            message (str): A 256-bit hex-encoded string representing the
                message to be sent to the CPA oracle

        Raises:
            TypeError: The message is not the correct length (64 hex characters)
            TypeError: the message is not a valid hex string
        """
        if len(message) != 64:
            raise TypeError(f"The message should be 256 bits but received {len(message)*4} bits")
        if not isHex(message):
            raise TypeError("Message input is not a hex string")

        self._message = message

    def make_oracle_payload(self, password:Password) -> dict:
        """Create a payload that the CPA encryption oracle understands

        Args:
            password (Password): A user password; you should make one if 
                you dont already have one. This is unique to the user.

        Returns:
            dict: a dictionary representing the JSON payload that will be 
                sent to the server via a POST request.
        """
        return {
            'password': password.password,
            'oracle_message': self.message
        }
    

class Ciphertext():
    """Create a ciphertext that the CPA server understands

        For a given message 'm' = m1||m2 and for some pseudorandom 
        function with key 'k' (f_k), we have: 

            Ciphertext = (r, c1, c2) where,

             r = a random nonce    (128 bits)
            c1 = f_k(r) XOR m2     (128 bits)
            c2 = f_k(m2) XOR m1    (128 bits)
        
    """
    def __init__(self, 
    hex_random_nonce:str = None, 
    hex_c1:str = None, 
    hex_c2:str = None,
    ciphertext_dict: dict = None
    )-> None:
        """Construct Ciphertext() and check that the inputs are correct

        Args:
            hex_random_nonce (str, optional): Hex encoded random nonce that is 
                128-bits long (32 hex characters). Defaults to None.
            hex_c1 (str, optional): Hex encoded c1 that is 128 bits long (32 hex
                characters). Defaults to None.
            hex_c2 (str, optional): Hex encoded c2 that is 128 bits long (32 hex
                characters). Defaults to None.
            ciphertext_dict (dict, optional): A dictionary containing the keys:
                random_nonce, c1, and c2 with the appropriate values. Defaults 
                to None.

        Raises:
            TypeError: Random nonce is not a valid hex string
            TypeError: C1 is not a valid hex string
            TypeError: c2 is not a valid hex string

        Returns:
            None: return None
        """
        if ciphertext_dict != None:
            self.from_json(ciphertext_dict)
            return None
        if hex_random_nonce != None:
            if not isHex(hex_random_nonce):
                raise TypeError("The random nonce input is not a hex string")
        if hex_c1 != None:
            if not isHex(hex_c1):
                raise TypeError("The C1 input is not a hex string")
        if hex_c2 != None:
            if not isHex(hex_c2):
                raise TypeError("The C2 input is not a hex string")
        
        self.random_nonce = hex_random_nonce
        self.c1 = hex_c1
        self.c2 = hex_c2
        
        return None

    def from_json(self, data: dict) -> None:
        """Marshall JSON into a Ciphertext that has already been constructed

        Args:
            data (dict): The data to be marshalled. Must have the keys:
                random_nonce, c1, and c2.

        Returns:
            None: return None
        """
        self.random_nonce = data['random_nonce']
        self.c1 = data['c1']
        self.c2 = data['c2']

        return None

    def to_json(self) -> dict:
        """Get a dictionary of the Ciphertext contents

        Returns:
            dict: The dict with ciphertext contents: random_nonce, 
                c1, and c2.
        """
        return {
            'random_nonce': self.random_nonce,
            'c1': self.c1,
            'c2': self.c2
        }


class Challenges():
    """Create a set of challenges that the CPA server understands
    """
    def __init__(self, messages:list) -> None:
        """Construct Challenges and check that the input list is valid

        Args:
            messages (list): A list of 20 hex-encoded strings each of size 
                256 bits (or 64 hex characters).

        Raises:
            ValueError: The number of messages is not 20

        Returns:
            None: return None
        """
        if len(messages) != 20:
            raise ValueError("The number of msgs in the messages list should be 20")
        
        self.messages = []
        messages = [messages[i:i+2] for i in range(0,20,2)]
        for message_pair in messages:
            self.messages.append(
                [Message(message_pair[0]), Message(message_pair[1])]
            )

        return None

    def make_challenges_payload(self, password:Password) -> dict:
        """Create a JSON payload for the challenge oracle

        Args:
            password (Password): a hex-encoded password

        Returns:
            dict: The challenge API payload as a dictionary
        """
        messages = []
        for message_pair in self.messages:
            messages.append([x.get_message()  for x in message_pair])

        return {
            'password': password.password,
            'messages': messages
        }


class Decisions():

    def __init__(self, 
        ciphertexts:List[Ciphertext] = None, 
        decisions: List[int] = None
    ) -> None:
        self.ciphertexts = ciphertexts
        self.decisions = decisions
        return None

    def make_decision_payload() -> dict:

        return {
            
        }

def query_encryption_oracle(
    hex_password:str,
    hex_message:str, 
    server_url:str = server_url + encryption_oracle_path,
    debug:bool = False
) -> Ciphertext:
    """Given a message, as the encryption oracle for a ciphertext

        Talk to the Encryption Oracle. Use this API to generate a 
        series of 20 messages that have some property that given
        two messages allows you to determine which of the two 
        messages was encrypted in the CPA game.

    Args:
        hex_password (str): A hex-encoded 128-bit password
        hex_message (str): A hex-encoded 256-bit message
        server_url (str, optional): The URL of the server including the
            path to the oracle. Defaults to 'https://ineedrandom.com/oracle'.
        debug (bool, optional): If true, show debug output. Defaults to False.

    Raises:
        ValueError: There server gave an error response code

    Returns:
        Ciphertext: The ciphertext received from the CPA server
    """
    trial_message = Message(hex_message)
    my_password = Password(hex_password)

    resp = requests.post(
        url=server_url, 
        json = trial_message.make_oracle_payload(my_password)
    )

    if debug:
        print(f"Status Code: {resp.status_code}")
        print(f"Response Body: {resp.text}")
    
    if resp.status_code != 200:
        raise ValueError(f"Received status code {resp.status_code}" +
            ". This means something went wrong: {resp.text}")

    ciphertext_dict = resp.json()['ciphertext']

    return Ciphertext(ciphertext_dict=ciphertext_dict)


def submit_challenges(
    hex_password:str, 
    messages:List[str],
    server_url:str = server_url + challenge_path,
    debug:bool = False
) -> List[Ciphertext]:
    """Given a set of 20 messages, query the challenge API

    Presumably, you have skillfully crafted a set of 20 messages
    that take advantage of the CPA vulnerability of the encryption
    oracle. Send these messages to the server and receive a set of
    10 ciphertexts.

    Recall that in the CPA game:

        1. You (the adversary A) send a set of 2 messages
        2. The oracle sends a ciphertext
        3. You decided if message 1 or message 2 was encrypted
        4. If you are able to distinguish between Enc(m1) vs. Enc(m2)
            better than epsilon, you win.

    Args:
        hex_password (str): A hex-encoded password
        messages (List[str]): A list of message pairs. [ [m1,m2], [m3,m4], ..., [m19,m20] ]
            where each message is a hex-encoded string of size 256 bits.
        server_url (str, optional): The URL of the challenge API. Defaults 
            to 'https://ineedrandom.com/challenges'.
        debug (bool, optional): Display debug output. Defaults to False.

    Raises:
        ValueError: The server responded with an error code

    Returns:
        List[Ciphertext]: A list of 10 ciphertexts which are represented as 
            the Ciphertext class: [ Ciphertext(), ..., Ciphertext()]
    """
    my_password = Password(hex_password)
    challenges = Challenges(messages)

    resp = requests.post(
        url=server_url, 
        json = challenges.make_challenges_payload(my_password)
    )

    if debug:
        print(f"Status Code: {resp.status_code}")
        print(f"Response Body: {resp.text}")
    
    if resp.status_code != 200:
        raise ValueError(f"Received status code {resp.status_code}" +
            f". This means something went wrong: {resp.text}")

    ciphertexts_list = resp.json()['ciphertexts']

    return [Ciphertext(ciphertext_dict=ciphertext_dict) for ciphertext_dict in ciphertexts_list]


def submit_decisions():

    return


def cpa_solution():
    return


if __name__ == "__main__":
    from os import urandom

    # Create 128-bit hex-encoded password
    pwd = urandom(16).hex()

    # Create a test message. This message does not
    # need to come from a random source. We do this
    # because it is convenient.
    message = urandom(32).hex()

    # Create a few test messages - 20 hex-encoded 
    # messages of size 256 bits. We pull these 
    # messages from urandom and convert them to hex
    msgs = [urandom(32).hex() for x in range(20)]

    # Query the encryption oracle
    returned_ciphertext = query_encryption_oracle(pwd, message)

    # Print the result
    print(returned_ciphertext.to_json())

    """
        This is where you would choose messages and send these
        messages to the encryption oracle. These chosen messages
        should allow you to distinguish between Enc(chosen_message) 
        and Enc(anything_else).
    """
    special_messages = cpa_solution()

    # Submit challenges
    ciphertexts = submit_challenges(pwd, msgs)
    #ciphertexts = submit_challenges(pwd, special_messages)

    # Print the challenges
    for item in ciphertexts:
        print(item.to_json())


def test_query_encryption_oracle():
    #fixed_msg
    #expected_ciphertext
    # do cpa encryption
    # assert

    pass


def test_submit_challenges():

    pass