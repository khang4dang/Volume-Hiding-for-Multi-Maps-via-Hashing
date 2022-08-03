#!/usr/bin/python

import os
import struct
import sys
from dotenv import load_dotenv
from prettytable import PrettyTable
from datetime import datetime
import time
from hurry.filesize import size

import numpy as np
import pandas as pd
import random
import datetime
import pickle
import mysql.connector
from Crypto.Cipher import AES

ALPHA = 1
N = 0
L_MAX = 0
T1 = []
T2 = []
STASH = []
T = 0
N_EVICT = 4 #20
DF = None

ENCRYPTION_KEY = b'Sixteen byte key'

bits = [0] * (64 * 1024)
K_PRF = random.Random()
K_PRF.seed("BitHash random numbers")
for i in range(64 * 1024):
    bits[i] = K_PRF.getrandbits(64)

def BitHash(s, h=0):
    for c in s:
        h = (((h << 1) | (h >> 63)) ^ bits[ord(c)])
        h &= 0xffffffffffffffff
    return h

def hashFunc(key, counter):
    ''' get two index values to hash into T1 and T2'''
    global T
    s = str(key) + str(counter)
    x = BitHash(s)          # hash twice 
    y = BitHash(s, x)
    size = T
    return x % size, y % size

def read_file(filename):
    global DF
    DF = pd.read_csv(filename, header=None, names=['partkey', 'suppkey'])

def print_hash_tables():
    global T, T1, T2
    for i in range(0, T):
        print(f"T1[{i}] = {T1[i]}")
    
    for i in range(0, T):
        print(f"T2[{i}] = {T2[i]}")

def set_up():
    '''hash values from db into T1, T2, Stash'''
    global ALPHA, N, N_EVICT, L_MAX, T1, T2, STASH, T, DF

    # Get Key-Value pairs from Table and num of keys
    db=[]

    DF = DF.sort_values('partkey')
    DF = DF.reset_index()
    for row in DF.itertuples():
        db.append((row[2], row[3]))

    N = DF.shape[0]
    T = int(np.ceil((1 + ALPHA) * N))
    T1 = [None] * (T)
    T2 = [None] * (T)
    STASH = [None] * int(np.ceil(0.3*len(db)))

    # SET L_MAX
    L_MAX = max(DF.groupby(by='partkey').size())


    print(f"N={N}\nT1 length={len(T1)}\nT2 length={len(T2)}\nStash length={len(STASH)}\nL_MAX={L_MAX}\n")
    print(f'Size of cleartext data:\t{(sys.getsizeof(db[0]) * N)}B')

    stash_index = 0
    counter = 1
    key = db[0][0]
    numRecords = 0

    for pair in db:
        inserted = 0
        
        if pair[0] != key: #reset counter
            key = pair[0]
            counter = 1

        index1, index2 = hashFunc(pair[0], counter) 
        
        # start the loop checking the 1st position in table 1
        pos = index1
        table = T1

        for i in range(N_EVICT):
            if table[pos] == None:          # if the position in the current table is empty
                table[pos] = pair                             # insert the pair there
                inserted = 1
                numRecords += 1
                break                                       # break the for loop
            pair, table[pos] = table[pos], pair             # else, evict item in pos and insert the item
                                                            # then deal with the displaced node
            if pos == index1:                               # if we're checking the 1st table right now,
                index1, index2 = hashFunc(pair[0], counter)   # hash the displaced pair,
                pos = index2                                  # and check its 2nd position 
                table = T2                                    # in the 2nd table (next time through loop)
            else:
                index1, index2 = hashFunc(pair[0], counter)   # otherwise, hash the displaced pair,
                pos = index1                                  # and check the 1st table position. 
                table = T1
        if inserted == 0:
            STASH[stash_index] = pair
            stash_index += 1
            inserted = 1
            numRecords += 1
        counter += 1
    #print(f'Stash:\t{STASH}')

def encrypt_hash_tables():
    '''encrypt key-value pairs in T1 and T2 using AES'''
    global T, T1, T2, ENCRYPTION_KEY
    count_rand_vals = 0
    for i in range(0, T):  # Pad null values
        if T1[i] == None:
            T1[i] = (random.randint(N, N + N), random.randint(N, N + N))
            count_rand_vals += 1
        if T2[i] == None: 
            T2[i] = (random.randint(N, N+N), random.randint(N, N + N))
            count_rand_vals += 1
        T1[i] = struct.pack('!QQ', T1[i][0], T1[i][1]) # store tuple values into 16B using struct
        T2[i] = struct.pack('!QQ', T2[i][0], T2[i][1]) # store tuple values into 16B using struct
        encrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM) #EAX, GCM
        T1[i] = (encrypt_cipher.nonce, encrypt_cipher.encrypt(T1[i])) # Store tag (7B), encrypted data (49B)
        encrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM) #EAX, GCM
        T2[i] = (encrypt_cipher.nonce, encrypt_cipher.encrypt(T2[i])) # Store tag (7B), encrypted data (49B)

    print(f"Number of fake values added:\t{count_rand_vals}")
    print(f'Size of encrypted data:\t{sys.getsizeof(T1[0]) * 2 * T}B')

def decrypt_table():
    global T1, T2, T, ENCRYPTION_KEY
    print("T1 decrypted table")
    for i in range(0, T):
        decrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=T1[i][0])
        plaintext = decrypt_cipher.decrypt(T1[i][1])
        tup = struct.unpack('!QQ', plaintext) #pickle.loads(plaintext)
        print(f"tup={tup}")
    
    print("\nT2 decrypted table")
    for i in range(0, T):
        decrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=T2[i][0])
        plaintext = decrypt_cipher.decrypt(T2[i][1])
        tup = struct.unpack('!QQ', plaintext) #pickle.loads(plaintext)
        print(f"tup={tup}")

def get_response(key_request):
    '''get values from T1 and T2 and match the hash index location'''
    global L_MAX, decrypt_cipher, STASH, T1, T2

    encrypted_result = PrettyTable()
    encrypted_result.field_names = ["value"]
    result = PrettyTable()
    result.field_names = ["Key", "Value"]
    T1_indexes = []
    T2_indexes = []
    count_fake = 0

    # build the request query
    for i in range(0, L_MAX):
        index1, index2 = hashFunc(key_request, i)
        T1_indexes.append(index1)
        T2_indexes.append(index2)

    # int are objects in Python that are 28B
    print(f'\nSize of input query:\t{sys.getsizeof(T1_indexes[0]) * 2 * L_MAX}B')

    for i in T1_indexes:
        encrypted_result.add_row([T1[i][1]])
        decrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=T1[i][0])
        plaintext = decrypt_cipher.decrypt(T1[i][1])
        tup = struct.unpack('!QQ', plaintext)
        if tup[0] == key_request:
            result.add_row([tup[0], tup[1]])
        else:
            count_fake+=1
    
    for i in T2_indexes:
        encrypted_result.add_row([T1[i][1]])
        decrypt_cipher = AES.new(ENCRYPTION_KEY, AES.MODE_GCM, nonce=T2[i][0])
        plaintext = decrypt_cipher.decrypt(T2[i][1])
        tup = struct.unpack('!QQ', plaintext)
        if tup[0] == key_request:
            result.add_row([tup[0], tup[1]])
        else:
            count_fake+=1
    
    print(encrypted_result)
    
    for pair in STASH:
        if pair == None:
            continue
        if pair[0] == key_request:
            result.add_row([pair[0], pair[1]])

    print(f'Size of encrypted output result:\t{sys.getsizeof(T1[0]) * 2 * L_MAX}B\n')
    print(f'Number of fake values in the answer:\t{count_fake}\n')
    print(result)

def main():
    global ALPHA
    file_choice = ''
    input_choice = int(input('\nWelcome to vMMM using Hashing!\n[1] Non-Skewed Dataset\n[2] Skewed Dataset\n[3] Test Dataset\n[4] Enter file name\n: '))
    if input_choice == 1:
        file_choice = 'non_skewed_dataset.csv'
    elif input_choice == 2:
        file_choice = 'skewed_dataset.csv'
    elif input_choice == 3:
        file_choice = 'test.csv'
    else:
        file_choice = input('Enter the name of file: ')
    read_file(file_choice)
    
    ALPHA = float(input('\nEnter an float (1.0, 0.95, etc) value for ALPHA: '))
    print(f'\nSetting up {file_choice} using L_PARTKEY and L_SUPPKEY with ALPHA = {ALPHA}\n')

    start = time.time()
    set_up()
    mid = time.time()
    print(f'Key-Value Pairs are hashed...{mid - start} secs')
    encrypt_hash_tables()
    mid2 = time.time()
    print(f'Hash Tables are encrypted...{mid2 - mid} secs')
    end = time.time()
    print(f'Time to hash and encrypt table = {end - start} secs')

    while True:
        choice = int(input('\nPlease enter\n[1] to make a selection query\n[2] to exit program\n: '))
        if choice == 1:
            search_key = int(input('Enter a L_PARTKEY to search:\t'))
            start = time.time()
            get_response(search_key)
            end = time.time()
            print(f'Time to run query = {end - start} secs\n')
        else:
            exit()

if __name__ == '__main__':
    main()