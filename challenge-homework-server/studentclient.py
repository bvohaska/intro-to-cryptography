import requests
from os import urandom

# Query the oracle

# Generate messages

# Query the challenger

# Request a decision from the decision API

#
# HW 2b
#
def do_payload(iv:bytes, ciphertext:bytes) -> dict:

    payload = {
        "iv": iv,
        "ciphertext": ciphertext
    }

    return payload


def do_padding_hax():
    """Defeat the padding oracle and decyrpt the ciphertext without the encryption key
    """
    url = "https://ineedrandom.com/paddingoracle"
    iv = bytes.fromhex("26d1634eca6a0222fcff1f6d7bc87ddd")
    ciphertext = bytearray.fromhex("d6c88784f890d6a24c5bf2f090c0aec7151c970066589f850df329ca127e031f638cbb004c563a6617c7b2fb09f17fc7")
    print(len(ciphertext))
    valid = "Valid"
    bad = "Invalid"

    #ciphertext[-1] = 197
    resp_data = "Valid"
    for index in range(34,len(ciphertext)):

        ciphertext_trial = ciphertext.copy()
        ciphertext_trial[index] = int.from_bytes(urandom(1),'little')
        payload = do_payload(iv.hex(), ciphertext_trial.hex())
    
        resp = requests.post(
            url=url,
            json=payload
        )
        if resp.text.find("Valid") < 0:
            print(f"Ciphertext index: {index}")
            print(f"The server response: {resp.text}")

if __name__ == "__main__":
    do_padding_hax()