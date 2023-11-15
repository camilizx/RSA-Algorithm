import random
import math
import base64

number_of_bits = 1024

# função para verificar se o número é primo rodando o teste de  Miller-Rabin
def miller_rabin(n, k):
    if (n == 2 or n == 3):
        return True
    if (n == 1 or n%2 == 0):
        return False
    r, s = 0, n-1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2,n-1)
        x = pow(a, s, n)
        if x == 1 or x == n-1:
            continue
        for _ in range (r-1):
            x = pow(x,2,n)
            if x == n-1:
                break
        else:
            return False
    return True

# função para converter binário para inteiro
def binary2int(binary):
    n = 0
    pow2 = 1
    for i in range(len(binary)-1, -1, -1):
        n += binary[i] * pow2
        pow2 *= 2
    return n

# função para gerar um valor ímpar aleatório com o primeiro e ultimo bit setado como 1 
def random_odd_value(number_of_bits):
    B = [0]*number_of_bits
    B[0] = 1
    B[-1] = 1
    for i in range(1, number_of_bits-1):
        B[i] = random.randint(0,1)
    return binary2int(B)

# função para gerar um número primo prováveln
def generate_probable_prime(number_of_bits):
    while True:
        n = random_odd_value(number_of_bits)
        if (miller_rabin(n, 40)):
            return n

# Algoritmo de Euclides para calcular o mdc
"""
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
"""

# Escolhe um valor de e tal que 1<e<phi(n) e gcd(phi(n), e) = 1.
def calculate_e(phi):
    while True:
        e = random.randint(2, phi - 1)
        if (math.gcd(e, phi) == 1):
            return e
        e += 1

# Encontra o inverso multiplicativo de 'a' módulo 'm'
def calculate_d(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0

def rsa():
    p = generate_probable_prime(number_of_bits)
    print (f"p: {p}")
    q = generate_probable_prime(number_of_bits)
    print (f"q: {q}")
    n = p*q
    phi = (p-1)*(q-1)
    e = calculate_e(phi)
    d = calculate_d(e, phi)

    return [n, e, d]

""""
def encode_message_base64(message):
    encoded_message = base64.b64encode(message.encode('utf-8')) # Codifica a mensagem usando base64
    integer_representation = int.from_bytes(encoded_message)   # Converte a representação base64 para um número inteiro
    return integer_representation
def decode_message_base64(message):
    bytes_representation = message.to_bytes(math.ceil(message.bit_length() / 8), byteorder='big') # Converte o número inteiro para bytes
    decoded_message = base64.b64decode(bytes_representation) # Decodifica a mensagem usando base64
    return decoded_message
"""

def encode(message, n, e):
    encoded_message = [pow(number, e, n) for number in message]
    return encoded_message

def decode(message, n, d):
    decoded_message = [pow(number, d, n) for number in message]
    decoded_message = ''.join(chr(i) for i in decoded_message)  # converter array de char para string
    return decoded_message

def main():
    message = "Hello World"
    message_in_ascii = [ord(c) for c in message]
    print ("Mensagem original em char: ", message_in_ascii)

    [n, e, d] = rsa()
    print (f"n: {n}, e: {e}, d: {d}")
    
    encoded_message = encode(message_in_ascii, n, e)
    print ("Mensagem codificada: ", encoded_message)
    
    decoded_message = decode(encoded_message, n, d)
    print ("Mensagem decodificada: ", decoded_message)

if __name__ == "__main__":
    main()