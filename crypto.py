# Crypto Module

##################################################################
##### TO PRINT WHEN IMPORTED
##################################################################

print("Welcome to the SFU Crypto Python Package")
print("Functions available for use:")
print("")
print("-------------------------------------------------------------")
print("Tools for Number Theory:")
print("-------------------------------------------------------------")
print("    gcd(a,b)")
print("    xgcd(a,b)")
print("    findModInverse(a,m)")
print("    eulerPhi(a)")
print("-------------------------------------------------------------")
print("Tools for Encryption/Decryption:")
print("-------------------------------------------------------------")
print("    shiftEncrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    shiftDecrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    transpositionEncrypt(key, message)") 
print("    transpositionDecrypt(key, message)")
print("    affineEncrypt(keyA, keyB, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')") 
print("    affineDecrypt(keyA, keyB, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    vigenereEncrypt(key, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    vigenereDecrypt(key, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    vigenereCipher(key, message, mode, symbolList):")
print("    substitutionEncrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("    substitutionDecrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("        keyIsValid(key, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')") 
print("        getRandomKey(symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ')")
print("-------------------------------------------------------------")
print("Tools for Cryptanalysis:")
print("-------------------------------------------------------------")
print("    getLetterCounts(message)")
print("    plotLetterCounts(lettercounts)")
print("    findRepeatSequencesSpacings(message)")
print("    indexOfCoincidence(message,m)")
print("    mIndexOfCoincidence(message1,message2,m)")



##################################################################
#####
#####     Number Theory Functions
#####
##################################################################

def gcd(a,b):
    """Return the GCD of a and b using Euclid's Algorithm."""
    while b > 0:
        a, b = b, a%b
    return a
    
    
def xgcd(a,b):
    """Extended GCD:
    Returns (gcd, x, y) where gcd is the greatest common divisor of a and b
    with the sign of b if b is nonzero, and with the sign of a if b is 0.
    The numbers x,y are such that gcd = ax+by."""
    prevx, x = 1, 0;  prevy, y = 0, 1
    while b:
        q, r = divmod(a,b)
        x, prevx = prevx - q*x, x  
        y, prevy = prevy - q*y, y
        a, b = b, r
    return a, prevx, prevy    

def findModInverse(a,m):
    """Return the modular inverse of a%m, which is the number x such that a*x = 1 mod m."""
    if gcd(a,m) != 1:
        return None # No mod inverse if a & m aren't relatively prime.
    
    # Calculate using the extended Euclidean algorithm
    return xgcd(a,m)[1]%m


def eulerPhi(a):
    """Return the number of positive integers less than
    a that are relatively prime to a"""
    if a == 1:
        return 1
    else:
        m = [n for n in range(1,a) if gcd(a,n)==1]
        return len(m) 



##################################################################
#####
#####     Shift Cipher (Monoalphabetic Substitution Cipher)
#####
##################################################################

def shiftEncrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the ciphertext of message encrypted using the Shift cipher with key. Default symbolList is A-Z"""
    return(shiftCipher(key, message, 'encrypt', symbolList))

def shiftDecrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the plaintext of message encrypted using the Shift cipher with key. Default symbolList is A-Z"""
    return(shiftCipher(key, message, 'decrypt', symbolList))     
        
def shiftCipher(key, message, mode, symbolList):
    ''' mode = 'encrypt' OR mode = 'decrypt' '''
    
    # Every possible symbol that can be encrypted:
    SYMBOLS = symbolList

    # Store the encrypted/decrypted form of the message:
    translated = ''
    
    for symbol in message:
    # Note: Only symbols in the SYMBOLS string can be encrypted/decrypted.
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)
        
            # Perform encryption(0)/decryption(1):
            if mode == 'encrypt':
                translatedIndex = (symbolIndex + key) % len(SYMBOLS)
            elif mode == 'decrypt':
                translatedIndex = (symbolIndex - key) % len(SYMBOLS)
            
            # Append the encrypted/decrypted symbol to the end of the translated string
            translated = translated + SYMBOLS[translatedIndex]
        else:
            # Append the symbol without encrypting/decrypting
            translated = translated + symbol

    # Output the translated string
    return translated




##################################################################
#####
#####    Affine Cipher (Monoalphabetic Substitution Cipher)
#####
##################################################################
# WARNING - First make sure the findModInverse function is executed 
# (i.e. loaded into python) since the Affine cipher uses this
# functions. To do this go up to the cell where this function 
# is defined and run the cell.
        
def affineEncrypt(keyA, keyB, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the ciphertext of message encrypted using the Affine cipher with keyA, keyB. Default symbolList is A-Z"""
    return affineCipher(keyA, keyB, message, 'encrypt', symbolList)

def affineDecrypt(keyA, keyB, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the plaintext of message encrypted using the Affine cipher with keyA, keyB. Default symbolList is A-Z"""
    return affineCipher(keyA, keyB, message, 'decrypt', symbolList)
        
    
def affineCipher(keyA, keyB, message, mode, symbolList):
    # Every possible symbol that can be encrypted:
    SYMBOLS = symbolList
    modInverseOfKeyA = findModInverse(keyA,len(SYMBOLS))  # used for decryption
    
    translated = ''
    for symbol in message:
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)
            if mode == 'encrypt': # Encrypt the symbol
                translated += SYMBOLS[(symbolIndex*keyA+keyB) % len(SYMBOLS)]
            elif mode == 'decrypt':  # Decrypt the symbol
                translated += SYMBOLS[(symbolIndex-keyB)*modInverseOfKeyA % len(SYMBOLS)]
        else:
            translated += symbol # Append the symbol without encrypting
            
    return translated    



##################################################################
#####
#####    Vigenere Cipher (Polyalphabetic Substitution Cipher)
#####
##################################################################

def vigenereEncrypt(key, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the ciphertext of message encrypted using the Vigenere cipher with key. Default symbolList is A-Z"""
    return vigenereCipher(key, message, 'encrypt', symbolList)


def vigenereDecrypt(key, message, symbolList = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Return the plaintext of message encrypted using the Vigenere cipher with key. Default symbolList is A-Z"""
    return vigenereCipher(key, message, 'decrypt', symbolList)


def vigenereCipher(key, message, mode, symbolList):
    translated = [] # Stores the encrypted/decrypted message string.
    
    # Every possible symbol that can be encrypted:
    LETTERS = symbolList
    
    keyIndex = 0
    key = key.upper()

    for symbol in message: # Loop through each symbol in message.
        num = LETTERS.find(symbol.upper())
        if num != -1: # -1 means symbol.upper() was not found in LETTERS.
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) # Add if encrypting.
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) # Subtract if decrypting.

            num %= len(LETTERS) # Handle any wraparound.

            # Add the encrypted/decrypted symbol to the end of translated:
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())

            keyIndex += 1 # Move to the next letter in the key.
            if keyIndex == len(key):
                keyIndex = 0
        else:
            # Append the symbol without encrypting/decrypting.
            translated.append(symbol)

    return ''.join(translated)



##################################################################
#####
#####    Substitution Cipher
#####
##################################################################

import random

def keyIsValid(key, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    keyList = list(key)
    lettersList = list(symbolList)
    keyList.sort()
    lettersList.sort()
    
    return keyList == lettersList

def getRandomKey(symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    key = list(symbolList)
    random.shuffle(key)
    return ''.join(key)

def substitutionEncrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    return substitutionCipher(key, message, 'encrypt', symbolList)

def substitutionDecrypt(key, message, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    return substitutionCipher(key, message, 'decrypt', symbolList)

def substitutionCipher(key, message, mode, symbolList='ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    translated = ''
    charsA = symbolList
    charsB = key
    if mode == 'decrypt':
        # For decrypting, we can use the same code as encrypting. 
        # We just need to swap where the key and LETTERS strings are used.
        charsA, charsB = charsB, charsA
    
    # Loop through each symbol in the message:
    for symbol in message:
        symIndex = charsA.find(symbol)
        if symIndex != -1:
            translated += charsB[symIndex]
        else:
            # Symbol is not in symbolList; just add it:
            translated += symbol
    
    return translated    


##################################################################
#####
#####    Transposition Cipher
#####
##################################################################

import math

def transpositionEncrypt(key, message):
    # Each string in ciphertext represents a column in the grid:
    ciphertext = [''] * key

    # Loop through each column in ciphertext:
    for column in range(key):
        currentIndex = column
        
        # Keep looping until currentIndex goes past the message length:
        while currentIndex < len(message):
            # Place the character at currentIndex in message at the
            # end of the current column in the ciphertext list:
            ciphertext[column] += message[currentIndex]

            # Move currentIndex over:
            currentIndex += key
            
    # Convert the ciphertext list into a single string value and return it:
    return ''.join(ciphertext)


def transpositionDecrypt(key, message):
    # The transposition decrypt function will simulate the "columns" and
    # "rows" of the grid that the plaintext is written on by using a list
    # of strings. First, we need to calculate a few values.

    # The number of "columns" in our transposition grid:
    numOfColumns = int(math.ceil(len(message) / float(key)))
    
    # The number of "rows" in our grid:
    numOfRows = key
    # The number of "shaded boxes" in the last "column" of the grid:
    numOfShadedBoxes = (numOfColumns * numOfRows) - len(message)
    
    # Each string in plaintext represents a column in the grid:
    plaintext = [''] * numOfColumns

    # The column and row variables point to where in the grid the next
    # character in the encrypted message will go:
    column = 0
    row = 0
    
    for symbol in message:
        plaintext[column] += symbol
        column += 1 # Point to the next column.

        # If there are no more columns OR we're at a shaded box, go back
        # to the first column and the next row:
        if (column == numOfColumns) or (column == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
            column = 0
            row += 1

    return ''.join(plaintext)




##################################################################
#####
#####    Cryptanalysis Functions
#####
##################################################################

# Letter Frequency Finder

def getLetterCounts(message):
    """Returns a dictionary with keys of single letters and values of the
    count of how many times they appear in the message parameter"""
    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    letterCount = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'E': 0, 'F': 0, 'G': 0, 'H': 0, 'I': 0, 'J': 0, 'K': 0, 'L': 0, 'M': 0, 'N': 0, 'O': 0, 'P': 0, 'Q': 0, 'R': 0, 'S': 0, 'T': 0, 'U': 0, 'V': 0, 'W': 0, 'X': 0, 'Y': 0, 'Z': 0}

    for letter in message.upper():
        if letter in LETTERS:
            letterCount[letter] += 1

    return letterCount


# we import a few libraries to help with plotting
import numpy as np
import matplotlib.pyplot as plt

def plotLetterCounts(letterCounts):
    """ input: use the output from 'getLetterCounts'
    Returns a bar plot of the frequency of the letters"""
    letterCountsKeys = [letter for letter in letterCounts]
    letterCountsValues = [letterCounts[letter] for letter in letterCountsKeys]
    x_pos = np.arange(len(letterCountsKeys))
    
    plt.bar(x_pos,letterCountsValues,align='center',alpha=0.75)
    plt.xticks(x_pos,letterCountsKeys)
    plt.ylabel('Frequency')
    plt.xlabel('Letters')
    plt.title('Letter Frequency in String of Text')
    plt.show()

    
    
# Special Functions for Cryptanalysis of Vigenere Cipher
# Kasiski Test: Find repeating patterns 

import re   # we use the regular expression module to do a bit of magic on line 3 and 11

NONLETTERS_PATTERN = re.compile('[^A-Z]')

def findRepeatSequencesSpacings(message):
    """ Goes through the message and finds any length 3 to 5 letter sequences
    that are repeated. Returns a dictionary with the repeated sequences as 
    the keys and values of a list of spacings (num of letters between the repeats)."""

    # Use a regular expression to remove non-letters from the message:
    message = NONLETTERS_PATTERN.sub('', message.upper())

    # Compile a list of seqLen-letter sequences found in the message:
    seqSpacings = {} # Keys are sequences, values are lists of int spacings.
    for seqLen in range(3, 6):
        for seqStart in range(len(message) - seqLen):
            # Determine what the sequence is, and store it in seq:
            seq = message[seqStart:seqStart + seqLen]

            # Look for this sequence in the rest of the message:
            for i in range(seqStart + seqLen, len(message) - seqLen):
                if message[i:i + seqLen] == seq:
                    # Found a repeated sequence.
                    if seq not in seqSpacings:
                        seqSpacings[seq] = [] # Initialize a blank list.

                    # Append the spacing distance between the repeated
                    # sequence and the original sequence:
                    seqSpacings[seq].append(i - seqStart)
    return seqSpacings



# Index of Coincidence
# WARNING: requires `getLetterCount` function to be executed (defined above)

def indexOfCoincidenceSingle(message):
    """Takes as input a string, returns the index of coincidence - the probability that 
    two randomly selected characters of the string are the same"""
    letterCounts = getLetterCounts(message)
    N=len(message)
    ioc = sum([letterCounts[letter]*(letterCounts[letter]-1) for letter in letterCounts.keys()])
    return round(ioc/(N*(N-1)),4)

def indexOfCoincidence(message,m):
    """Takes as input a string, and a positive integer m. The message string is 
    split into m substrings:  by writing the message in columns of m characters 
    and taking the rows as substrings. 
    Returns the index of coincidence for the string corresponding to each row"""
    messages = ['']*m
    currentIndex = 0
    for i in range(len(message)):
        messages[i%m] += message[i]
    return list(map(indexOfCoincidenceSingle,messages))


# Mutual Index of Coincidence

def mIndexOfCoincidenceSingle(message1,message2):
    """Takes two strings as input, returns the mutual index of coincidence - the probability that 
    a randomly selected character from each string is the same"""
    letterCounts1 = getLetterCounts(message1)
    letterCounts2 = getLetterCounts(message2)
    N1=len(message1)
    N2=len(message2)
    mioc = sum([letterCounts1[letter]*(letterCounts2[letter]) for letter in letterCounts1.keys()])
    return round(mioc/(N1*N2),4)

def mIndexOfCoincidence(message1,message2,m):
    """Takes as input a string, and a positive integer m. The message string is 
    split into m substrings:  by writing the message in columns of m characters 
    and taking the rows as substrings. 
    Returns the index of coincidence for the string corresponding to each row"""
    messages1, messages2 = ['']*m, ['']*m
    mioc = []
    currentIndex = 0
    for i in range(len(message1)):
        messages1[i%m] += message1[i]
    for i in range(len(message2)):
        messages2[i%m] += message2[i]    
    for i in range(m):
        mioc.append(mIndexOfCoincidenceSingle(messages1[i],messages2[i]))
    return mioc



