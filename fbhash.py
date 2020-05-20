#!/bin/env python3

from math import log10
from math import sqrt
from random import choice
from string import ascii_uppercase
from string import ascii_lowercase

"""
FBHash A new similarity hashing scheme for digital forensics
By : Monika Singh and Douglas R. White et al.
"""

'''
The following part is for demonstration purpose only.
'''
# Generate random string with uppercase and lowercase ascii characters
def randStr(chars = ascii_uppercase + ascii_lowercase, N=52):
	return "".join(choice(chars) for _ in range(N))
N = 1000
dataSet = []
for _ in range (0, N):
	dataSet.append(randStr())
dataSet.append("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm")
dataSet.append("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM")
dataSet.append("qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm")
#print(dataSet)


# Chunck calculator. Finds and returns a list of chunks in data object D with chunk length k.
def chunkCalc(D, n):
#	print("[+] Calculating chunks from the document... ", end="")
	Ch = []			   # Chunk list
	k = 7 			   # Chunk length/Window Size

	for i in range(0, n - 6 ):  # For all elements from index 0 to ((n - 7) + 1)
		Ch.append(D[i: (i + 7)])
#	print("Done")
#	print("Chunks of Document : ", Ch)
	return Ch

# Calculate the rolling Hash of each chunk using Rabin-Karp rolling hash function
# H = C1*a^(k-1) + C2*a^(k-2) + C3*a^(k-3) + ... + Ck*a^(0) modulus n
# Where "a" is a constant, k is window size (chunk length), n is a large prime number, 
# C1,C2,..,Ck are the input characters (ASCII Values)
# Hnew = ( a*H - C0*a^(k) + incoming byte ) modulus n
# EQN : RollingHash(Ch(i+1)) = a*RollingHash(Chi) - Ci*a^(k) + C(i+k) modulus n
# Max value of H can be an unsigned 64 bit number
# All possible ASCII values of Ci (input characters) = 256 (ASCII Value)
# All possible values of "a" (constant) = 256 (size of alphabet)
# Value of k should satisfy the following
#			2^(64) - 1 >= 256 * 256^(k-1)
# Let k = 7
#			2^(64) > 2^(8) * (2^(8))^6 = 2^(56)
# TODO : Optimize this functions with respect to the equation. 
# NB   : Lazy implementation. Too much computational time wasted!
def rollHash(Ch):
#	print("[+] Calculating RollingHash of ", len(Ch), " chunks... ", end="")
	H = []   		# Hash list
	a = 255  		# Constant
	n = 801385653117583579  # Large prime number (larger than 2^56 = 72057594037927940)
	h = 0	 		# Temporary variable
	#For every chunk in the chunk list, take one by one and find the rolling hash
	for Ci in Ch: 
		k = 7

		# For every element in the chunk, convert it to ascii and do the math
		for elm in list(Ci):
			h +=  ord(elm)*pow(a, (k - 1))
			k = k - 1

		H.append(h % n)
#	print("Done")
#	print("List of RollingHashes : ", H)
	return H

# Chunk Frequency Calulation. 
# Parameters are D (data object) and N (length of data object D)
# Store the rolling hash value in a dictionary where the key is the rolling hash value
# and the value associated with the key is the frequency of occurance of the chunk in D
def chunkFrq(H):
	print("[+] Calculating chunk frequency... ", end="")
	ChfD = {}	# Dictionary of chunk frequency
	uniq = set(H) 	# Filters out unique values from the list
	
	# For evert unique element, find its count
	for elm in uniq:
		ChfD[elm] = H.count(elm)
	
	print("Done")
#	print("Hash Table of Chunk Frequency : ", ChfD)
	return ChfD

# Calulate and return the chunk weight of each chunk based on frequency.
# Chwgt = 1 + log(chunk frequency) ; log to th base 10
def chunkWgt(ChfD):
	print("[+] Calculating Chunk Weight... ", end="")
	Chwgt = {}

	# For every element from the list of keys, calculate chunk weight and add it to a dictionary
	for elm in ChfD.keys():
		Chwgt[elm] = 1 +log10(ChfD[elm])

	print("Done")
#	print("Chunk Weight of various chunks : ", Chwgt)
	return Chwgt

# Document Frequency Calculation: Number of documents that contain the chunk Ch. Represented by dfCh
# Take the list of all roll hashes of the document and check its frequency with the roll hash 
# of the sample documents. 
# Find the chunks of all the documents, find the rolling hashes. store it in a temporary variable.
# Check the frequency of hashes in H to the ones in the temporary list. 
def docFrq(H):
	print("[+] Calculating Document Frequency... ", end="")
	h = [] 				   # Temporary variable to hold the rolling hashes
	dfCh = {}			   # Document Frequency
	global dataSet			   # For referring to the global dataset generated.
	
	for d in dataSet:		   # Take every data object
		Ch = chunkCalc(d, len(d))  # Find the chunks
		h.extend(rollHash(Ch))	   # Calculate the rolling hashes and put it into temporary variable

	for uniq in set(H):		   # For all the unique hashes in list of the original document
		dfCh[uniq] = h.count(uniq) # Find the frequency of the chunk and store it int he dictionary

	print("Done")
#	print("Document Frequency hash table : ", dfCh)
	return dfCh

# Document Weight : Measure of uniqueness or informativeness of chunk Cn. Represented by idfCn
# idfCh = log(N/dfCh)
def docWgt(dfCh):
	print("[+] Calculating Document Weight... ", end="")
	global N 			 	
	idfCh = {}

	for h in dfCh.keys(): 		# For every rolling hash in the hash table 
		if dfCh[h] > 0:		# If the frequency value is greater zero, only then proceed
			idfCh[h] = log10(pow((N/dfCh[h]), 2))
			continue	# Break the loop and start the next iteration
		idfCh[h] = 1		# Otherwise set the document weight to One
	print("Done")
#	print("Document Weight : ", idfCh)
	return idfCh

# Similarity based Digest Generation function.
# Chunk Score : WDxCh = chwgt * idfCh
# digest(D1) = WD1C0, WD1C2, ..., WD1Ch-1
# Find the digest vector of all the documents
def chunkScr(Chwgt, idfCh):
	print("[+] Calculating Chunk Score... ", end="")
	WDxCh = []			# Digest list

	for key in Chwgt.keys():	# Since the keys of both the dictionaries are the same, we can use either
		WDxCh.append(Chwgt[key] * idfCh[key])

	print("Done")
#	print("Digest Vector of Document : ", WDxCh)
	return WDxCh

# Calculate FbHash of document D
def fbHash(D):
	print("\n =============== Frequency based Hash Calculation ============== \n")
	n      = len(D)	 			# Length of the data object/document
	Ch     = chunkCalc(D, n)		# Chunks (Type : list)
	H      = rollHash(Ch)			# Find and return the list of rolling hash of every chunk(Type : List)
	ChfD   = chunkFrq(H)			# Hash table of chunk frequency (Type : Dict)
	Chwgt  = chunkWgt(ChfD)			# Find the weight of each chunk w.r.t its frequency (Type : Dict)
	dfCh   = docFrq(H)			# Find frequency of chunks in different Documents (Type : Dict)
	idfCh  = docWgt(dfCh)			# Calculate the document weight (Type : Dict)
	digest = chunkScr(Chwgt, idfCh)		# Calculate chunk score using chunk and document weight (Type : list)
	print("\n =============================== Done =========================== \n")

	return digest

# Similarity based Score Generation function.
# 			    (Sum of all WD1Ci * WD2Ci where i = 0 to n-1)	 
# Similarity(D1, D2) =  ----------------------------------------------------- * 100
#			sqrt(Sum of all (WD1Ci)^2)*sqrt(Sum of all (WD2Ci)^2)
def smlrScrCalc(d1, d2):
	print("[+] Calculating similiarity score... ", end="")
	numerator    = 0
	denomenator  = 0
	denom1       = 0
	denom2       = 0

	for i in range(0, len(d1)):
		numerator += d1[i] * d2[i]
		denom1    += pow(d1[i], 2)
		denom2    += pow(d2[i], 2)

	denomenator = sqrt(denom1)*sqrt(denom2)

	score = (numerator/denomenator)*100
	print("Done")
	return score



def main():
# D1 and D2 are our documents aka data object
	D1 = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"
	D2 = D1

# d1 and d2 are our digest of D1 and D2 respectively
	d1 = fbHash(D1)
	d2 = fbHash(D2)

# score is the similiarity scrore of the two vectors
	score = smlrScrCalc(d1, d2)
	print("Similiarity score of D1 and D2 : ", round(score, 5), "%")
	return 0

if __name__ == '__main__':
	main()
