import sys
import requests
from Crypto.PublicKey import RSA
import json
import argparse

''' python wrapper around factordb '''

def check_args():
    parser = argparse.ArgumentParser(description='Factordb lookup tool')

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-n",
                    help='RSA n',
                    type=int)

    group.add_argument("-p", "--pubkey",
    				help='Path to a public key',
                    type=open)

    parser.add_argument("-e",
                        help="RSA e",
                        type=int,
                        default=65537)

    return parser.parse_args()

def egcd(a,b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, n):
    g, x, y = egcd(a, n)
    if g != 1: #a and n are'nt coprime
        raise Exception('Modular inverse does not exist')
    else:
        return x % n


def reconstructFull(p,q,e=65537):
    """
    Create a  full key from p and q
    """
    n  = p*q
    phi = (p-1) * (q-1)
    d = modinv(e,phi)
    return  RSA.construct((n,e,d))

if __name__ == "__main__":

    args = check_args()

    if args.n is None:
        k =  RSA.importKey(args.pubkey.read())
        n = k.n
        e = k.e
        print("[*]Your public key e is {}".format(e))
        print("[*]Your public key n is {}".format(n))
    else:
        n = args.n
        e = args.e

    url = "http://factordb.com/api.php?query="

    r = requests.get(url+str(n))
    try :
        jsonData = json.loads(r.text)
    except:
        sys.exit("[-]Error parsing factordb's reponse")

    if jsonData["status"] == "FF":
        p,q = int(jsonData["factors"][0][0]), int(jsonData["factors"][1][0])
        if (p*q != n) :
            sys.exit("[-]N is'nt the product of two primes. Leaving ...")

        print("[+]N is factorized!")
        print("[+]{} = {} * {}".format(n,p,q))
        print("[+]Here is your key : ")
        key = reconstructFull(p,q,e)
        print(key.exportKey().decode())
    else:
        print("[-] N i'snt factorized on factordb.")

