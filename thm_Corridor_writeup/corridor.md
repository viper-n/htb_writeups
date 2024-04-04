# Corridor Writeup
This is an entry level box with a focus on [IDOR](https://en.wikipedia.org/wiki/Insecure_direct_object_reference) vulnerabilities.
> Insecure direct object reference (IDOR) is a type of access control vulnerability in digital security. This can occur when a web application or application programming interface uses an identifier for direct access to an object in an internal database but does not check for access control or authentication. For example, if the request URL sent to a web site directly uses an easily enumerated unique identifier (such as http://foo.com/doc/1234), that can provide an exploit for unintended access to all records.

## Basic Scanning
Basic network scanning using `nmap` yielded only one open port, nothing too drastic.

![image](https://github.com/viper-n/htb_writeups/assets/83149207/5e8d6e99-3d42-4de9-9ef3-2d3fe1277e31)

## Website
Browsing to the website shows an image of a corridor with multiple doors. At first glance nothing stands out, but then you realize you can click on the individual doors.

![image](https://github.com/viper-n/htb_writeups/assets/83149207/15cc0207-7028-4a64-93a9-6beded173ca1)

Each door contains the same image of a white room, notice the URI:

![image](https://github.com/viper-n/htb_writeups/assets/83149207/ad97a32f-24b0-4061-aec0-470058b2aaf4)

My immediate reaction was to send this to crackstation.net, and sure enough... It's simply an MD5 hash of a number. All the doors are in sequence, so it's just a series of hashes between 1 to 13. You can also see these in the source code of the page.

![image](https://github.com/viper-n/htb_writeups/assets/83149207/3e0dcd1f-4f82-4dbe-bce7-c1090f2eac12)

## FUZZing the URLs
I started converting integers to hashes using `md5sum`, without any luck. I was thinking forward. Wrote a short script to help me generate these hashes, and then tried fuzzing them using `ffuf`. Unfortunately, all hashes from 14 to 1000 failed...

![image](https://github.com/viper-n/htb_writeups/assets/83149207/201ccc9b-591a-4a6a-8ac3-5e667d8eeaf5)
![image](https://github.com/viper-n/htb_writeups/assets/83149207/a30aceb9-82cf-4548-916e-e7dcc250d4c4)

## From Zero to...
Then I simply tried the hash for 0, and viola! Pretty easy and chill room.. :) for a change!

![image](https://github.com/viper-n/htb_writeups/assets/83149207/1d673c22-3719-4c8b-b0b6-3af7a6044e69)
![image](https://github.com/viper-n/htb_writeups/assets/83149207/f3c42e12-adad-4775-81b5-76021e873d1a)

