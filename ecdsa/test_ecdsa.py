from ecdsa import SigningKey, NIST256p,NIST384p
from time import time_ns
import random
import string
import numpy as np




sk = SigningKey.generate(curve=NIST256p)

vk = sk.verifying_key
sign_time_lst=[]
verify_time_lst=[]
f=open("results/ecdsa265.txt","w")

f.write("Signing, Verify")
for i in range(10000):
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=60))
    random_string=random_string.encode("utf-8")


    sign_time=time_ns()
    signature = sk.sign(random_string)
    sign_time=time_ns()-sign_time
    sign_time_lst.append(sign_time)

    verify_time=time_ns()
    vk.verify(signature, random_string)
    verify_time=time_ns()-verify_time
    verify_time_lst.append(verify_time)

    f.write(f"{sign_time},{verify_time}\n")
# f.write(f"Media: {np.average(sign_time_lst)}\n{np.std(verify_time_lst)}\n")

print("NIST256p")
print(f"Signing:Media({np.average(sign_time_lst)}), STD({np.std(sign_time_lst)})")
print(f"Verify:Media({np.average(verify_time_lst)}), STD({np.std(verify_time_lst)})")

sign_time_lst.clear()
verify_time_lst.clear()
sk = SigningKey.generate(curve=NIST384p)

vk = sk.verifying_key

f=open("results/ecdsa384.txt","w")
f.write("Signing, Verify")
for i in range(10000):
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=60))
    random_string=random_string.encode("utf-8")


    sign_time=time_ns()
    signature = sk.sign(random_string)
    sign_time=time_ns()-sign_time
    sign_time_lst.append(sign_time)

    verify_time=time_ns()
    vk.verify(signature, random_string)
    verify_time=time_ns()-verify_time
    verify_time_lst.append(verify_time)
    f.write(f"{sign_time},{verify_time}\n")

# f.write(f"Media: {np.average(sign_time_lst)}\n{np.std(verify_time_lst)}\n")
print("NIST384p")
print(f"Signing:Media({np.average(sign_time_lst)}), STD({np.std(sign_time_lst)})")
print(f"Verify:Media({np.average(verify_time_lst)}), STD({np.std(verify_time_lst)})")