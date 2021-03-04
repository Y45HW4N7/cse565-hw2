import hashlib
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

sha256_hash = SHA256.new(data=b"1kb.txt")
sha256_hash = SHA256.new(data=b"10MB.txt")

privateKey = DSA.generate(2048)
publicKey = privateKey.public_key()


signer = DSS.new(privateKey, "fips-186-3")
signature = signer.sign(sha256_hash)
print(signature, sha256_hash.hexdigest())

verifier = DSS.new(publicKey, "fips-186-3")
try:
    verifier.verify(sha256_hash, signature)
    print("verification successful")
except ValueError:
    print("verificaiton failed")
