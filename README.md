# Volume-Hiding for Multi-Maps via Hashing
 
## Instruction

### 1. Installation

i.	Install Python 3.9.7 and package manager pip(3)

ii.	Install virtual environment manager for avoid package dependency issues
-	Conda: https://docs.anaconda.com/anaconda/install/index.html
-	venv: https://docs.python.org/3/library/venv.html

iii.	Create a new virtual environment
-	Conda: https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html
-	Venv: https://docs.python.org/3/library/venv.html

iv.	Create a  new folder and download:
-	vhMMM_main.py file
-	Requirements.txt
-	csv files

v.	Open a terminal for all the next prompts
-	Run pip(3) install requirements.txt to install all dependencies

### 2. Execution

i.	Open a terminal

ii.	Run python(3) vhMMM_main.py

iii.	Follow the prompts on screen to select a dataset and run queries for it
-	Note: program must be rerun per dataset selection

## I. Overview
Volume-hiding structured encryption of multi-maps help solve severe consequences in volume leakage which is a prominent threat to the security of cryptographic cloud-based databases. In this project, our group will partially stimulate volume-hiding implementations of the research paper[^1], in which the performance of all private queries to an untrusted server is maintained by sharing the same (as the largest) response size; in other words, the number of responses (volume) for any query are hidden from the adversarial server. Also, the responses are originated from the actual ciphertexts containing many dummy results to make a query look uniform with others before being outsourced to the adversarial server. In this report, we first introduce the overview of the algorithm including two main parts: the setup and the query. Then, we will present the development and the execution of the project.

## II. Algorithm

This project focuses on the design and implementation of a structured encryption (STE) scheme, the volume-hiding encrypted multi-maps (EMMs), in which the volume refers to the number of associated values of any key. To address the issue caused by a passive attacker solely observing EMM accesses to exploit the volume leakage of queries (and somehow to reconstruct the private plaintext), a volume-hiding EMM not only can enable the storage of keys associated to a sequence of multiple values but also can hide the response length of a query. In this way, the scheme effectively mitigates the leakage in security caused by volume-abusing attacks. In this section, we present the algorithm overview of the database set-up and the database query to illustrate the volume-hiding EMMs against such adversaries. The set-up requires three main steps: cuckoo hashing to store the values into two tables (table T1 & table T2), and Stash; filling empty slots with dummy values; and, encrypting all values in T1, T2, and Stash before saving them in the server. The query asks the server to send client encrypted values from T1, T2, and Stash, then the client will decrypt these values.

### 1. DB Set-up

To understand the implementation, let us look into some generic definitions on encrypting and storing volume-hiding multi-maps to perform queries in a private manner.

**Data structure:**

Considering a multi-map (MM) primitive which is a collection of m key to value vector pairs (key-tuple pairs) ${(key,\vec{v})}$, we could get/put tuples associated with a specific key in MM with similar notions as a dictionary. 

**Cryptographic tools:**

Pseudorandom functions (PRF) are polynomial- time computable functions that cannot be distinguished from a truly random function by any adversary. The IND-CPA encryption scheme used in this paper is random-ciphertext-secure against chosen-plaintext attacks, which requires ciphertexts to be computationally indistinguishable from random even if the adversary adaptively accesses the encryption oracle. It can be obtained from the AES PRF-based encryption scheme.

**Volume hiding:**

Volume hiding requires that the number of values associated with any single key remains unknown. This is very important because it is a property of the leakage functions in a context where the adversary receives the setup and query leakage of a chosen multi-map. Passive adversaries who can observe all EMM accesses still cannot actively perform adversarial chosen accesses. Moreover, they do not know the plaintext multi-map used to generate EMM. An EMM who cannot determine the actual volume of any key in the multi-map is considered volume-hiding against passive adversaries. Note, the number of values associated with different keys can be different. We denote the maximum number of values associated by $l$. In this application, the client will always be sending the prefix of exactly $2l$ evaluations. We are able to convey these $2l$ PRF evaluations using exactly one PRF evaluation in such a way that the server can securely expand the single PRF evaluation to the required $2l$ PRF evaluations. This optimization reduces the bandwidth from the client to the server from $2l$ PRF outputs to just one PRF output.

An adversary has a high level of “controlling” the data owner who keeps explicitly authorizing many queries, that an actively malicious server can exploit toward exposing the entire multi-map. The volume-hiding scheme in this paper use less server storage and improve query overhead. Also, it remains meaningful in a realistic setting that the server cannot actively sabotage the data owner or would not risk be being caught. This also matches the required strength of the adversary in volume-abusing attacks.

**Cuckoo hashing:**

Hashing is known as a solution to assign a set of objects to some servers. The hash function, taking either (the identifier of) an object or a server as input, outputs $s$ bits. For large $s$, the probability of the collision of identifiers is negligible. Each object will be assigned to the server.

Cuckoo hashing consists of two algorithms Build and Search. Given $n$ key-value pairs, Build constructs Table 1 and Table 2 consisting arrays T1 and T2 each with the capacity to hold $t=(1+α)*n$ pairs for any constant $α>0$. The Build algorithm inserts the pairs one at the time using two hash functions $h1$, $h2$ and first places the pair $X$ in corresponding location in T1. If the location in T1 is empty, we are done. If the location is currently occupied by another pair $Y$, $Y$ is evicted, and the algorithm attempts to inserting $Y$ in corresponding location in T2. Similarly, if the location is empty, we are done. Otherwise, we evict the pair $Z$ found in T2 and try to insert $Z$ in the location of T1 specified by $h1$, and so on. Cuckoo hashing guarantees that a pair (key, value) is found either at T1 or T2. Thus, Search only retrieves two table locations. We say that cuckoo hashing fails if a key-value pair is not inserted after $Θ(log n)$ evictions.

Cuckoo hashing with a Stash introduces a stash $S$ of some fixed capacity $s$. After $Θ(log n)$ evictions, if a key-value pair has not been inserted yet, the pair is be inserted into the stash. Cuckoo hashing with a stash fails if strictly more than $s$ items are attempted to be inserted into the stash. The introduction of the stash reduces the failure probability exponentially in the stash size.
 
For Setup, the server receives the EMM, which contains the ciphertexts of all key-value tuples and randomly sampled Cuckoo hashing slots. Thus, the setup leakage only contains the data size.

For example, let us consider a set of key-value pairs as below:

k1 - v1, v2, v3, v4

k2 - v1, v2, v3

k3 - v1, v2

k4 - v1, v2, v3, v4, v5, v6, v7

k5 - v1, v2

Our purpose is to use Cuckoo hashing to store the values into empty Table T1, Table T2, and Stash (Figure 1).

<p align="center">
<img width="400" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Figure_1.png">
</p>
<p align="center"><b>
Figure 1: Empty T1, T2, and Stash
</b></p>

To do that, we first populate the dictionary with the missing values for all keys to mitigate leakage, the results are as below:

k1 - v1, v2, v3, v4, v5, v6, v7

k2 - v1, v2, v3, v4, v5, v6, v7

k3 - v1, v2, v3, v4, v5, v6, v7

k4 - v1, v2, v3, v4, v5, v6, v7

k5 - v1, v2, v3, v4, v5, v6, v7

Then, we use Cuckoo hashing to store the values into: Table T1, Table T2, and Stash. We also fill empty slots with dummy values (Figure 2).

<p align="center">
<img width="400" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Figure_2.png">
</p>
<p align="center"><b>
Figure 2: Filled T1, T2, and Stash
</b></p>

Finally, we encrypt all values in T1 & T2 and save in Server. Note that we randomly pick a PRF seed for Cuckoo hashing and an encryption key.

### 2. DB Query

For Query, the client requests the server sends encrypted values from T1, T2, and Stash. Then, the client will do the decryption part. The server will know $l$, the maximum volume of the input multi-maps by the size of any query token. It could determine the repetition of the same query and the common slots accessed by different queries. 

We now move onto the query operation for our STE scheme. The Query algorithm executed by the client will simply send the $2l$ values to the server. The server executes Reply by returning the encrypted values located at locations in the tables. The client retrieves the tuple of associated values by decrypting all table locations in the server’s response as well as checking the stash.

In our example, we get all the values that match $k2$. The server returns two times max value length of values (in this case, max value length equals to $7$). Thus, server will return 2 x 7 = 14 values.

An adversary with the knowledge of EMM could adaptively issue queries and try to match the corresponding access intersection with any prior background information about the actual volume. This seems to be inherent when we “reuse” real slots for realizing volume-hiding EMM efficiently. Passive adversaries cannot exploit such kinds of strategies. Intuitively, the response length for any key remains hidden since the slots for different keys are pseudorandom as our scheme decides them via pseudorandom functions.

In the example, the query part is summarized as the steps below:
- Client will decrypt response
- Concatenate the values that match $k2$. Ignore the values that don’t match or random
- Check Stash 
- Return $[v3, v1, v2]$

The figure below shows that the client gets all the values that match $k2$.

<p align="center">
<img width="400" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Figure_3.png">
</p>
<p align="center"><b>
Figure 3: Example of Client Request
</b></p>


## III. Development

For the project development, the volume-hiding STE scheme for multi-maps vhMM is followed by these steps mentioned in the paper. The construction will use pseudorandom family of functions and an IND-CPA secure encryption scheme. The steps extracted from the paper[^1] are:

**Setup:**

<p align="left">
<img width="500" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Figure_4.png">
</p>

**Request & Response:**

<p align="left">
<img width="420" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Figure_5.png">
</p>

In our implementation, we use the BitHash hashing function. Also, a random function setups a list of random 64-bit values to be used by BitHash and seeds the generator to produce repeatable results. This is useful in the event that client code needs a new hash function like Cuckoo hashing.

To finish the EMM setup, the client outsources the ciphertext of each key-value tuple and its location. To query for a key, the client issues a query to find slots related to it. The server then carries out discovery for each slot from the tables and returns the ciphertext stored. Due to the slot arrangement in the setup, the ciphertexts surely contain all the real values associated with the queried key, and there will be one and only one ciphertext (either associated with the queried key or another key) for each of the $l$ slots of any key, thus maintaining the same response volume (i.e., $l$) for any key.

## IV. Results

<p align="center"><b>
Table 1: System Settings
</b></p>
<p align="center">
<img width="600" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Table_1.png">
</p>

<p align="center"><b>
Table 2: Data Encryption Running Time
</b></p>
<p align="center">
<img width="600" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Table_2.png">
</p>

<p align="center"><b>
Table 3: Encryption Details
</b></p>
<p align="center">
<img width="600" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Table_3.png">
</p>

<p align="center"><b>
Table 4: Query Execution Running Time
</b></p>
<p align="center">
<img width="600" src="https://github.com/khang4dang/Volume-Hiding-for-Multi-Maps-via-Hashing/blob/main/images/Table_4.png">
</p>

---
<p align="center"><b>
Khang Dang & Vrushali Koli
</b></p>

[^1]: Sarvar Patel, Giuseppe Persiano, Kevin Yeo, and Moti Yung. 2019. Mitigating Leakage in Secure Cloud-Hosted Data Structures: Volume-Hiding for Multi-Maps via Hashing. In Proceedings of the 2019 ACM SIGSAC Conference on Computer and Communications Security (CCS '19). Association for Computing Machinery, New York, NY, USA, 79–93. DOI: https://doi.org/10.1145/3319535.3354213
