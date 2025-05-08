from time import time_ns
import oqs
from pprint import pprint

NUMBER_OF_EXECUTION=10000

print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("Enabled signature mechanisms:")
sigs = oqs.get_enabled_sig_mechanisms()
pprint(sigs, compact=True)


#https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa.html
# ['Dilithium2', 'Dilithium3', 'Dilithium5', 'ML-DSA-44', 'ML-DSA-65',
#  'ML-DSA-87', 'Falcon-512', 'Falcon-1024', 'Falcon-padded-512',
#  'Falcon-padded-1024', 'SPHINCS+-SHA2-128f-simple', 'SPHINCS+-SHA2-128s-simple',
#  'SPHINCS+-SHA2-192f-simple', 'SPHINCS+-SHA2-192s-simple',
#  'SPHINCS+-SHA2-256f-simple', 'SPHINCS+-SHA2-256s-simple',
#  'SPHINCS+-SHAKE-128f-simple', 'SPHINCS+-SHAKE-128s-simple',
#  'SPHINCS+-SHAKE-192f-simple', 'SPHINCS+-SHAKE-192s-simple',
#  'SPHINCS+-SHAKE-256f-simple', 'SPHINCS+-SHAKE-256s-simple', 'MAYO-1', 'MAYO-2',
#  'MAYO-3', 'MAYO-5', 'cross-rsdp-128-balanced', 'cross-rsdp-128-fast',
#  'cross-rsdp-128-small', 'cross-rsdp-192-balanced', 'cross-rsdp-192-fast',
#  'cross-rsdp-192-small', 'cross-rsdp-256-balanced', 'cross-rsdp-256-fast',
#  'cross-rsdp-256-small', 'cross-rsdpg-128-balanced', 'cross-rsdpg-128-fast',
#  'cross-rsdpg-128-small', 'cross-rsdpg-192-balanced', 'cross-rsdpg-192-fast',
#  'cross-rsdpg-192-small', 'cross-rsdpg-256-balanced', 'cross-rsdpg-256-fast',
#  'cross-rsdpg-256-small']
Claimed_NIST_Level_5=['Dilithium5','ML-DSA-87', 'SPHINCS+-SHA2-256f-simple','SPHINCS+-SHA2-256s-simple','SPHINCS+-SHAKE-256f-simple','SPHINCS+-SHAKE-256s-simple']
message = "This is the message to sign".encode()

#warm up executions
for i in range(1000):
    with oqs.Signature('Dilithium5') as signer:
            with oqs.Signature('Dilithium5') as verifier:
               
                # Signer generates its keypair
                signer_public_key = signer.generate_keypair()
                # Optionally, the secret key can be obtained by calling export_secret_key()
                # and the signer can later be re-instantiated with the key pair:
                # secret_key = signer.export_secret_key()

                # Store key pair, wait... (session resumption):
                # signer = oqs.Signature(sigalg, secret_key)

                # Signer signs the message
                
                signature = signer.sign(message)
                # Verifier verifies the signature
                
                is_valid = verifier.verify(message, signature, signer_public_key)
                


# Create signer and verifier with sample signature mechanisms
for alg in Claimed_NIST_Level_5:
    sigalg = alg
    f=open(f"results/{sigalg}.csv", "w")
    f.write(f"Signature,Verify\n")
    print(f"{sigalg}")
    for i in range(NUMBER_OF_EXECUTION):
        with oqs.Signature(sigalg) as signer:
            with oqs.Signature(sigalg) as verifier:
               
                # Signer generates its keypair
                signer_public_key = signer.generate_keypair()
                # Optionally, the secret key can be obtained by calling export_secret_key()
                # and the signer can later be re-instantiated with the key pair:
                # secret_key = signer.export_secret_key()

                # Store key pair, wait... (session resumption):
                # signer = oqs.Signature(sigalg, secret_key)

                # Signer signs the message
                sign_time=time_ns()
                signature = signer.sign(message)
                sign_time=time_ns()-sign_time
                # Verifier verifies the signature
                
                verify_time=time_ns()
                is_valid = verifier.verify(message, signature, signer_public_key)
                verify_time=time_ns()-verify_time

                f.write(f"{sign_time},{verify_time}\n")
