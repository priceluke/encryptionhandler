# RSA Encryption Wrapper - Java

## What is it?
This class can allows for RSA plain text ascii encryption & decryption. It was initially created to work with the TCP Chat, also avalible on Git, but can be used in other programs as a way to keep public/private keys encapsulated while offering an interface to encrypt/decrypt text.

Please feel free to use.

## How RSA Works

RSA relies on the idea that very large prime factors are extremly hard to extract from a large (enough) number. RSA isn't impossible to break, although it is considered heuristically secure as it would take a suitably long amount of time to seperate the two primes.

### Public Key
Two primes are generated, *p* and *q*.

These are multiplied to create *pq*=*n*.

A small (ish) exponent is generated. *e*.

*n*&*e* make up the public key.

### Private Key
*phi* = (*p*-1)(*q*-1)
*private key* = (2(*phi*)+1)/*e*
