**Wiener RSA Attack**

Weak RSA primitives, such as an unusually small public or private exponents, can lead to attacks on data encrypted with that key. One such attack on a weak private exponent is known as Wiener's Attack. Specifically, this attack exploits a particular vulnerability in RSA when the private exponent 𝑑 d is too small relative to the public exponent 𝑒. Usually the public exponent *e* is a much smaller number, but if *e* is a very large number, then *d* becomes very small, which leads to this vulnerability. If you have the public RSA key and the ciphertext, start by using the python script below to extract *e,* having `key.pub` as the weak RSA public key and `flag.enc` as the encrypted ciphertext:
    
    ```python
    from Crypto.PublicKey import RSA
    
    def get_pubkey(f):
    	with open(f) as pub:
    		key = RSA.importKey(pub.read())
    	return (key.n, key.e)
    	
    N, e = get_pubkey('./key.pub')
    
    print(f'{e = }')
    ```
    
If you find out that *e* is a very large number, you can conclude that *d* is indeed very small. Next write another function to `getCiphertext` to load the ciphertext and convert it to a number so we can work with it:
    
    ```python
    from Crypto.PublicKey import RSA
    
    def get_pubkey(f):
    	with open(f) as pub:
    		key = RSA.importKey(pub.read())
    	return (key.n, key.e)
    
    def get_ciphertext(f):
    	with open(f, 'rb') as ct:
    		return bytes_to_long(ct.read())
    ```
    
Use a known python module, `owiener`, that uses the Wiener attack. You can find the script [here](https://github.com/orisano/owiener).
    
    ```python
    d = owiener.attack(e, N)
    ```
    
 Now you can decrypt the ciphertext after obtaining the value of *d*:
    
    ```python
    def decrypt_rsa(N, e, d, ct):
    	pt = pow(ct, d, N)
    	return long_to_bytes(pt)
    ```
    
You can include all the above in one function, call it `rsa_break` , and the full script becomes:
    
    ```python
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    
    import owiener
    
    def get_pubkey(f):
    	with open(f) as pub:
    		key = RSA.importKey(pub.read())
    	return (key.n, key.e)
    
    def get_ciphertext(f):
    	with open(f, 'rb') as ct:
    		return bytes_to_long(ct.read())
    
    def decrypt_rsa(N, e, d, ct):
    	pt = pow(ct, d, N)
    	return long_to_bytes(pt)
    	
    def rsa_break():
    	N, e = get_pubkey('./key.pub')
    	ct = get_ciphertext('./flag.enc')
    	d = owiener.attack(e, N)
    	flag = decrypt_rsa(N, e, d, ct)
    	print(flag)
    	
    if __name__ == '__main__':
        rsa_break()
    ```
