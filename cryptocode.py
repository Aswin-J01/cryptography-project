import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tinyec import registry
import secrets
from Crypto.Cipher import AES
import hashlib, binascii
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
from sklearn.cluster import KMeans
from sklearn import metrics
import streamlit as st



#---------------------------------------------------------------------------
"Load a dataset"
st.write("DATASET LOADED SUCESSFULLY....")
df=pd.read_csv('Cybersecuritydataset.csv')

#----------------------------------------------------------------------------

st.write("CHECKING ANY VALUE ARE MISSING IN DATASET")
df.isnull().sum()

#--------------------------------------------------------------------------
len(df)
nRow, nCol = df.shape
st.write(f'There are {nRow} rows and {nCol} columns')
#-----------------------------------------------------------------------

st.write(f"Duplicated rows: {df.duplicated().sum()}")

#---------------------------------------------------------------------------

curve = registry.get_curve('brainpoolP256r1')

def compression(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def cal_keys_for_encrypt(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def cal_keys_for_decrypt(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey

privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

st.write("\n")
st.write("Generated Keys...")
st.write("Private Key:", hex(privKey))
st.write("Public Key:", compression(pubKey))

(encryptKey, ciphertextPubKey) = cal_keys_for_encrypt(pubKey)
st.write("Ciphertext PubKey:", compression(ciphertextPubKey))
st.write("Encryption Key:", compression(encryptKey))

decryptKey = cal_keys_for_decrypt(privKey, ciphertextPubKey)
st.write("Decryption Key:", compression(decryptKey))

st.write("\n")

def AES_Encryption(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def AES_Decryption(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ECC_bit_key_generation(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def ECC_Encryption(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    ciphertext, nonce, authTag = AES_Encryption(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

column_names = list(df.columns)

result = df.values

st.write("Encrypting  CSV file...")  
empty = []
#empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encryption(en, pubKey)
        b = binascii.hexlify(s[0])
        encoded_text = b.decode('utf-8')
        empty.append(encoded_text)
        #print(f"Encoded Text : {encoded_text}")
 #-------------------------------------------------------------------------------------       
def ECC_Decryption(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    plaintext = AES_Decryption(ciphertext, nonce, authTag, secretKey)
    return plaintext

st.write(" Decrypting the CSV file...")  
empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encryption(en, pubKey)       
        de = ECC_Decryption(s, privKey)
        decoded_text = de.decode('utf-8')
        empty_decoded.append(decoded_text)
        #print(f"Decoded Text  : {decoded_text}")
#---------------------------------------------------------------------------------------------
encrypted_df = pd.DataFrame(np.array(empty).reshape(149,4),columns = column_names)
decrypted_df = pd.DataFrame(np.array(empty_decoded).reshape(149,4),columns = column_names) 

st.write("Encryption Completed and written as encryption.csv file")
encrypted_df.to_csv(r'C:/Users/STUDENT/CloudMe/encrypted.csv',index = False)

st.write("Decryption Completed and written as decryption.csv file")
decrypted_df.to_csv(r'C:/Users/STUDENT/CloudMe/decrypted.csv',index = False)

#-----------------------------------------------------------------------------------------

from easygui import *
task = "Enter the Admin Login  number to be Search"
text_query = "Enter the Query to be Search"

Key = "Enter the Key to be Search"
  
# window title
title = "Query"
task1 = enterbox(task, title)
  
# creating a integer box
str_to_search1 = enterbox(text_query, title)

Key = passwordbox(Key, title)



if task1 in ["163052"]:
    st.write("Reterival Cybersecurity ")
    global data1   
    data = pd.read_csv("Cybersecuritydataset.csv")
    if (Key=='Cybersecurity'):    
        st.write("Correct Key")
        data1=data[data['Keyword'].str.contains(str_to_search1)]
        
        st.write(data1)    
    else:
        st.write("Incorrect Key")
        
        
 #-----------------------------------------------------------------------------       

from PIL import Image

def text_to_bin(text):
    binary = ' '.join(format(ord(char), '08b') for char in text)
    return binary.split()

def hide_text(image_path, secret_text):
    img = Image.open(image_path)
    binary_secret_text = text_to_bin(secret_text)
    binary_secret_text_length = len(binary_secret_text)

    width, height = img.size
    pixel_values = list(img.getdata())

    if len(pixel_values) < binary_secret_text_length:
        raise ValueError("Image not big enough to hide the text")

    index = 0
    for i in range(height):
        for j in range(width):
            if index < binary_secret_text_length:
                r, g, b = img.getpixel((j, i))

                r_binary = list(format(r, '08b'))
                r_binary[-1] = binary_secret_text[index]
                r = int(''.join(r_binary), 2)

                index += 1

                if index < binary_secret_text_length:
                    g_binary = list(format(g, '08b'))
                    g_binary[-1] = binary_secret_text[index]
                    g = int(''.join(g_binary), 2)

                    index += 1

                if index < binary_secret_text_length:
                    b_binary = list(format(b, '08b'))
                    b_binary[-1] = binary_secret_text[index]
                    b = int(''.join(b_binary), 2)

                    index += 1

                img.putpixel((j, i), (r, g, b))
            else:
                img.save(r'C:/Users/STUDENT/CloudMe/outputimage.png')
                return

    img.save(r'C:\Users\STUDENT\CloudMe/outputimage.png')
    binary_secret_text = ''

    width, height = img.size
    pixel_values = list(img.getdata())

    for i in range(height):
        for j in range(width):
            r, g, b = img.getpixel((j, i))
            binary_secret_text += bin(r)[-1]
            binary_secret_text += bin(g)[-1]
            binary_secret_text += bin(b)[-1]

    binary_secret_text = [binary_secret_text[i:i+8] for i in range(0, len(binary_secret_text), 8)]
    hidden_text = ''.join([chr(int(char, 2)) for char in binary_secret_text])
    return hidden_text

def reveal_text(image_path):
    img = Image.open(image_path)
    binary_secret_text = ''

    width, height = img.size
    pixel_values = list(img.getdata())

    for i in range(height):
        for j in range(width):
            r, g, b = img.getpixel((j, i))
            binary_secret_text += bin(r)[-1]
            binary_secret_text += bin(g)[-1]
            binary_secret_text += bin(b)[-1]

    binary_secret_text = [binary_secret_text[i:i+8] for i in range(0, len(binary_secret_text), 8)]
    hidden_text = ''.join([chr(int(char, 2)) for char in binary_secret_text])
    return hidden_text

# Example usage:
# Hide text inside an image
hide_text(r'E:/secue storage/sourcecode.py/IMG1/img1.jpg', 'This is a secret message.')


# Retrieve hidden text from the image
hidden_message = reveal_text(r'C:\Users\STUDENT\CloudMe/outputimage.png')
st.write("Hidden message:", hidden_message)


