# Understanding java signing process

Before walking through the code, lets understand the java signing process.

# The providers
As  the matured library, java ecosystem can handle multiple encryption, decryption, hashing and the other cryptographic method. 
Now in order to ensure that at the high level, all the algorithm works similarly, have abstracts out the cryptographic operations. Its implementation class also gives the liberty to write and implement your own algorithm. To ensure the flexibility java have the notion of the providers. A provider is the cryptographic library that handles the operation related to the given algorithm and operation. Before using any algorithm, ensure that the provider is installed in the system.
Generally there would be two major providers,
1. Bouncy Castle
2. Sun

### CMSSignedData
This is the signed data that contains the message, the public key and the certfificates of the signer. Each message can be signed by more than one entity and the signer would have all the objects related the to the signature.


### About .p12 file
.p12 file are the files that stores the certificates as well as the private key. Ideally they should be locked by the password. To generate the .p12 file
