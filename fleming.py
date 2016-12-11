"""
Dean Fleming <deanf1@umbc.edu>
CMSC 443-01
RSA Project

Encrypts and decrypts messages using the RSA cryptosystem

Notes:
	- My code will remove all whitespace from inputted plaintext messages
	- I tested this with several messages and it worked for every one
	- I tested my Miller-Rabin prime-finder with smaller sized numbers (i.e. 
	  5-bit, 6-bit numbers) and the results were prime everytime. I did this
	  as I could not find an online prime tester that handled 512-bit primes
	- I ran my prime-finder 20 times and the iterations it took to find a prime
	  varied from 2 to 622 times and everything in between for each prime
	- I timed my prime-finder 20 more times and the time it took to find a prime
	  varied anywhere from ~0.032 to ~0.664 seconds for each prime
	- I timed the entire algorithm (finding two primes and decrypting) another
	  20 times and it took anywhere from ~0.065 to ~0.891 seconds
	- I tested this code on a Dell laptop with an Intel i7-6500U @ 2.60GHz
	  and 8GB of RAM

"""

import random
import time

"""
getprime(bits)
Returns an almost guaranteed prime number of bit size "bits"
"""
def getPrime(bits):

	# counts how many iterations it takes to find a prime
	iterationCount = 0

	# gets the time of the code starting
	primeTimeStart = time.time()

	foundComposite = True
	while (foundComposite):
		foundComposite = False

		# generate a random odd integer of the required bits
		n = random.getrandbits(bits)
		if not (n & 1):
			n += 1

		# finding k and m for Miller-Rabin
		k = 0
		m = 0
		q = n - 1
		while not (q & 1):
			q = q / 2
			k += 1
		m = q

		# run Miller-Rabin 10 times
		for i in range(10):
			if not (millerRabin(k, m, n)):
				iterationCount += 1
				foundComposite = True
				break
	
	# gets the time of the code ending
	primeTimeEnd = time.time()

	#print primeTimeEnd - primeTimeStart
	#print iterationCount

	return n

""" 
Algorithm 5.7: millerRabin(k, m, n)
[Based on pseudocode from Stinson book]
Returns True if n is probably prime 
"""
def millerRabin(k, m, n):
		a = random.randint(1, n - 1)
		b = pow(a, m, n)
		if ((b - 1) % n == 0):
			return True
		for i in range(k):
			if ((b + 1) % n == 0):
				return True
			else:
				b = pow(b, 2, n)
		return False

"""
Algorithm 5.3: multiplicativeInverse(a, b)
[Based on pseudocode from Stinson book]
Solves b^-1 mod a
"""
def multiplicativeInverse(a, b):
	a0 = a
	b0 = b
	t0 = 0
	t = 1
	q = a0 // b0
	r = a0 - q * b0
	while r > 0:
		temp = (t0 - q * t) % a
		t0 = t
		t = temp
		a0 = b0
		b0 = r
		q = a0 / b0
		r = a0 - q * b0
	if b0 != 1:
		return False
	else:
		return t

"""
RSAEncrypt(x, n, b)
Encrypts the message x using public key (n, b) via RSA
"""
def RSAEncrypt(x, n, b):
	return squareAndMultiply(stringToInt(x), n, b)

"""
RSADecrypt(y, n, b)
Decrypts the message y using private key (n, a) via RSA
"""
def RSADecrypt(y, n, a):
	return intToString(squareAndMultiply(y, n, a))
	
"""
Algorithm 5.5: Square-and-Multiply(x, n, c)
[Based on pseudocode from Stinson book]
Solves x^c mod n
"""
def squareAndMultiply(x, n, c):
	# convert c into binary, reverse it, and find its length
	cbin = bin(c)[2:]
	cbin = cbin[::-1]
	l = len(cbin)

	z = 1
	for i in range(l - 1, -1, -1):
		z = pow(z, 2, n)
		if cbin[i] == '1':
			z = (z * x) % n
	return z

"""
stringToInt(string)
Encodes string into an integer as shown in Stinson Exercise 5.12 
"""
def stringToInt(string):
	# convert string to a list of letters
	letters = list(''.join(string.lower().split()))

	# represents letters as a base 26 number and calculates it into base 10
	sum = 0
	i = len(letters) - 1
	for letter in letters:
		sum += (ord(letter) - 97) * (pow(26, i))
		i -= 1
	return sum

"""
intToString(integer)
Decodes an integer to a string as shown in Stinson Exercise 5.12 
"""
def intToString(integer):
	string = []

	# loops until we completely divide 26's out of integer
	while integer:
		string.append(chr((integer % 26) + 97))
		integer //= 26

	# returns the result in reverse
	return ''.join(string[::-1])

def main():

	# gets the time of the code starting
	RSATimeStart = time.time()
	
	# generate our two large primes p and q
	p = getPrime(512)
	q = getPrime(512)

	# calculating phi and n from p and q
	phi = (p - 1) * (q - 1)
	n = p * q

	"""
	Using 65537 for b is better than finding a random b for two reasons:
	- I don't have to waste time generating primes and testing the gcd since it
	  is already guranteed to be prime and thus coprime with n
	- 65537 is a Fermat prime, meaning in binary its 10000000000000001, which
	  means it can be bit-wise operated on with few carries
	"""
	b = 65537
	
	# calculates a for our private key
	a = multiplicativeInverse(phi, b)

	# public and private key tuples
	publicKey = (n, b)
	privateKey = (n, a)

	""" COMMENT OUT IF USING A CERTAIN PUBLIC KEY FILE
	# outputs the public key to a file
	publicKeyOutputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_key.txt", 'w')
	publicKeyOutputFile.write(str(publicKey[0]))
	publicKeyOutputFile.write("\n")
	publicKeyOutputFile.write(str(publicKey[1]))
	publicKeyOutputFile.close()
	#"""

	""" COMMENT OUT IF USING A CERTAIN PRIVATE KEY FILE
	# outputs the private key to a file
	privateKeyOutputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_privatekey.txt", 'w')
	privateKeyOutputFile.write(str(privateKey[0]))
	privateKeyOutputFile.write("\n")
	privateKeyOutputFile.write(str(privateKey[1]))
	privateKeyOutputFile.close()
	#"""

	"""
	# FOR ENCRYPTION TESTING PURPOSES ONLY
	# allows the user to input a message, encrypts it, and outputs the encryption
	message = raw_input("Input a message: ")
	encrypted = RSAEncrypt(message, *publicKey)
	cipherTextOutputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_cipher.txt", 'w')
	cipherTextOutputFile.write(str(encrypted))
	cipherTextOutputFile.close()
	#"""

	# reads the input file and gets the cipher text from it
	cipherTextInputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_cipher.txt", 'r')
	encrypted = long(cipherTextInputFile.read())
	cipherTextInputFile.close()

	# reads the private key file and extracts the private key
	privateKeyInputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_privatekey.txt", 'r')
	privateKey = [long(line.rstrip('\n')) for line in privateKeyInputFile]
	privateKeyInputFile.close()

	# decrypts the cipher text and outputs the plain text to a file
	decrypted = RSADecrypt(encrypted, *privateKey)
	plainTextOutputFile = open("C:/Users/dfleming/Documents/CMSC443/fleming_xstr.txt", 'w')
	plainTextOutputFile.write(str(decrypted))
	plainTextOutputFile.close()

	# gets the time of the code ending
	RSATimeEnd = time.time()

	#print RSATimeEnd - RSATimeStart

main()