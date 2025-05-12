from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from time import time_ns
import random
import string
import numpy as np
import os
import csv

# Criar diretório 'results' se não existir
if not os.path.exists("results"):
    os.makedirs("results")

runs=10000
warmUp=1000

def run_test(self, curve:ec.EllipticCurve):
    # Create keys
    sk = ec.generate_private_key(
        curve,
    )

    vk = sk.public_key()
    sign_time_lst=[]
    verify_time_lst=[]

    algorithm = curve.name

    # WarmUp
    for _ in range(warmUp):
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=60)).encode("utf-8")
        signature = sk.sign(
                random_string,
                ec.ECDSA(hashes.SHA256())
            )
        try:
                vk.verify(
                    signature,
                    random_string,
                    ec.ECDSA(hashes.SHA256())
                )
        except:
            pass

    # Actual run
    with open("results/{}.csv".format(algorithm),"w") as f:
        writer = csv.writer(f)
        writer.writerow(["Signing (ns)", "Verify (ns)"])
        
        for i in range(runs):
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=60)).encode("utf-8")

            sign_time=time_ns()
            signature = sk.sign(
                random_string,
                ec.ECDSA(hashes.SHA256())
            )
            sign_time=time_ns()-sign_time
            sign_time_lst.append(sign_time)

            verify_time=time_ns()
            try:
                vk.verify(
                    signature,
                    random_string,
                    ec.ECDSA(hashes.SHA256())
                )
                
            except InvalidSignature:
                print(f"AVISO: Verificação de P-256 falhou na iteração {i}!")
                pass
        
            verify_time=time_ns()-verify_time
            verify_time_lst.append(verify_time)

            writer.writerow([sign_time, verify_time])
        # f.write(f"Media: {np.average(sign_time_lst)}\n{np.std(verify_time_lst)}\n")

    print(algorithm)
    print(f"Signing:Media({np.average(sign_time_lst)}), STD({np.std(sign_time_lst)})")
    print(f"Verify:Media({np.average(verify_time_lst)}), STD({np.std(verify_time_lst)})")
    
curves= [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()]

for curve in curves:
    run_test("", curve)

