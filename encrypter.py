# imports
import argparse, secrets, getpass
import glob, os
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# cmd line arguments
parser = argparse.ArgumentParser()

parser.add_argument("-i", "--Input", help = "Input file name", required=True)
parser.add_argument("-o", "--Output", help = "Output file name")
parser.add_argument("-d", "--Dir", help = "Dir name")

args = parser.parse_args()


input_file_path = args.Input
output_file_path = args.Output
dir_path = args.Dir

output_file_path = './output.py'
dir_token = {}
main_file_path = f'./temp297269/{os.path.basename(input_file_path)}'

if args.Dir is not None and args.Input is None:
    input_file_path = input('Enter the main py file')

# input password
while True:
    password = getpass.getpass('Enter password ')
    password2 = getpass.getpass('Confirm password ')
    if password != password2:
        print('passworrd not matching')
    else:
        break

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


# iterate and tokonize all files in directory
if dir_path is not None:
    for subdir, dirs, files in os.walk(dir_path):
        for filename in files:
            filepath = subdir + os.sep + filename
            if filename != os.path.basename(input_file_path):
                with open(filepath, 'rb') as f:
                    data = f.read()
                token = password_encrypt(data, password)
                dir_token.update({filepath.replace(dir_path, "temp297269"):token})
            else:
                main_file_path = filepath.replace(dir_path, "temp297269")



with open(input_file_path, 'rb') as f:
    script = f.read()

token = str([main_file_path , password_encrypt(script, password)])
dir_token = str(dir_token)

# template for output file
template = """
import os, ast, shutil, argparse
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

parser = argparse.ArgumentParser()
parser.add_argument("-o", help = "make a copy of ur file", dest='Output', action='store_true')
parser.set_defaults(Output=False)
args = parser.parse_args()

backend = default_backend()
iterations = 100_000


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))
def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)



dir_token = {}
token = {}
# get password
while True:
    password = getpass.getpass('Enter password ')
    try:
        decrypted_script = password_decrypt(token[1], password)
        break
    except Exception as e:
        print(str(e))
        print('Incorrect password. Try again')

try:
    os.makedirs('temp297269')
except Exception:
    pass
with open(token[0], 'wb') as f:
    f.write(decrypted_script)

# decrypt all files in directory
if bool(dir_token):
    for key, values in dir_token.items():
        if not os.path.exists(os.path.dirname(key)):
            try:
                os.makedirs(os.path.dirname(key))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(key, 'wb') as f:
            f.write(password_decrypt(values, password))

print('--------------------------------------------------')
print()
os.system('python ' + token[0])

if not args.Output:
    shutil.rmtree('temp297269')
"""

with open(output_file_path, 'w') as f:
    f.write(template.format(dir_token,token))
