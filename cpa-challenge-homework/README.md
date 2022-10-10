# Homework Challenge Server

## Homework 2a Instructions

This is the first question of Homework 2 (the first major homework for the first half of the semester).

A description of the problem is below. You will interact with the CPA challenger at `https://ineedrandom.com` to complete the assignment. To understand the web APIs please visit: `https://ineedrandom.com/docs` 

If you have any issues interacting with the homework server at the URL above, please contact Brian Vohaska at `bvohaska@gmail.com`, then contact the professor at `dapon@umd.edu`.

You will note that the CPA Challenger requires a password. This password will be choosen (randomly!) by you and should be a unique 128-bit hex-encoded string. Please use this string throughout all of your queries. If you are working in a group, each person should perform the computation themselves from their own computer, and they should all choose their own password.

Make sure to list your collaborators + any references you used on this entire homework.

Your submission here (on Canvas) should be simply

1. your password
1. the 128-bit hex-encoded string that is your Proof Of Completion (PoC)

Additionally, please submit any source code that you used to complete this assignment. Attach it below the PoC string. Do not share your PoC string with anyone (even within your groups).

## Homework 2b Instructions

Decrypt the ciphertext

```python
iv = "26d1634eca6a0222fcff1f6d7bc87ddd"

ciphertext = "d6c88784f890d6a24c5bf2f090c0aec7151c970066589f850df329ca127e031f638cbb004c563a6617c7b2fb09f17fc7"
```
You have access to a decryption oracle that is not `CCA-secure` and uses PKCS#7 padding at the `/paddingoracle` API. The decryption oracle will respond to decryption queries with `Valid Padding` or `Invalid Padding`. You will receive no other information. PKCS#7 can be treated as PKCS#5 in this scenario.

Using your knoweldge of the CCA-security security game and PKCS#5 from the lecture, you should be able to decrypt this ciphertext.

## The CPA Challenge Game

Bob is trying to talk to Alice. He is using a `CPA-secure` encryption scheme as indicated by the class. But Bob wants to be more efficient than the natural construction of 

```text
ct = (r, c) = (r, f_k(r) XOR m)
```

In particular, Bob comes up with the following encryption algorithm: 

```text
Enc_k(m1||m2) = (r, f_k(r) XOR m2, f_k(m2) XOR m1)
```

**You** are the adversary in the CPA-security experiment.

Your job is to convince the CPA Challenger that given 2 messages and a ciphertext, you can identify which message generated the provided ciphertext. 

You may ask as many questions to the encryption oracle as needed (in 128-bits, hex-encoded format). Using the `/oracle` API on the challenge server.

Once you have figured out how to defeat the CPA Challenge game, you will produce a sequence of `10 challenge message-pairs` which are pairs of messages in a list (in total, 20 messages, each of 128-bit length, hex-encoded). You will then send these messages to the CPA Challenger at the `/challenges` API on the homework server. You will then receive a list of 10 ciphertexts. You must now figure out which message is encrypted under the ciphertext.

Once you have figured this out, you will need to send you answers to the `decision oracle` at the `\decision` API on teh homework server. This answer will eb a on a list of 10 ciphertexts along with an indication of which message generated each ciphertext (either the first message "1" or the second message "2").

You can query any of these interfaces as many times as you wish.

If you succeed, the decision oracle will respond with a special success message and a proof of completion.(A PRF (under the server's private key) applied to your password). Submit your chosen password and your PoC (PRF value on your password) to collect your homework points.