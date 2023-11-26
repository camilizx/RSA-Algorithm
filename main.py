import random
import math
import base64
import hashlib 
import os

number_of_bits = 512

# Função para verificar se o número é primo rodando o teste de  Miller-Rabin
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

# Função para imprimir em formato byte
def bytes2string(message):
    return (''.join(format(x, '02x') for x in message))

# Função para converter binário para inteiro
def binary2int(binary):
    n = 0
    pow2 = 1
    for i in range(len(binary)-1, -1, -1):
        n += binary[i] * pow2
        pow2 *= 2
    return n

# Função para converter inteiro para bytes
def int2bytes(number):
    return number.to_bytes((number.bit_length() + 7) // 8, 'big')

# Função para gerar um valor ímpar aleatório com o primeiro e ultimo bit setado como 1 
def random_odd_value(number_of_bits):
    B = [0]*number_of_bits
    B[0] = 1
    B[-1] = 1
    for i in range(1, number_of_bits-1):
        B[i] = random.randint(0,1)
    return binary2int(B)

# Função para gerar um número primo prováveln
def generate_probable_prime(number_of_bits):
    while True:
        n = random_odd_value(number_of_bits)
        if (miller_rabin(n, 40)):
            return n

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

# Função que gera os parâmetros do RSA
def rsa_parameters():
    p = generate_probable_prime(number_of_bits)
    q = generate_probable_prime(number_of_bits)
    print (f"p:{p} q: {q}")
    n = p*q
    phi = (p-1)*(q-1)
    e = calculate_e(phi)
    d = calculate_d(e, phi)
    return [n, e, d]

def rsa_encode(padded_message, n, e):
    return pow(padded_message, e, n)

def rsa_decode(message, n, d):
    decoded_message = [pow(number, d, n) for number in message]
    decoded_message = ''.join(chr(i) for i in decoded_message)  # converter array de char para string
    return decoded_message

# Converte um inteiro para uma string de octetos de comprimento xLen
def I2OSP(x, x_len):
    if x >= 256**x_len:
        raise ValueError("Número muito grande pra converter")
    return x.to_bytes(x_len, byteorder='big')

# Converte uma string de octetos para um inteiro
def OS2IP(X):
    return int.from_bytes(X, byteorder='big')

# MGF (mask generation function) é uma função de máscara geradora baseada em hash
def MGF(seed, mask_len):
    t = b''
    for i in range(0, math.ceil(mask_len/len(seed))):
        c = i.to_bytes(4, byteorder='big')
        t += hashlib.sha1(seed + c).digest()
    return t[:mask_len]

#H: SHA3. Hlen = tamanho em bytes da saída da função de hash
#G: MGF. Função de máscara geradora.
#(n,e) = chave pública do recipiente. k = comprimento em bytes do n
# M = mensagem a ser criptografada. Um bytes de tamanho mLen <= k - 2hlen - 2
# L = rótulo opcional.
# C = mensagem criptografada. Um octeto de tamanho = k
# k = comprimento em bytes do n

def rsa_oaep(n, e, M, L, k):
    h_len = hashlib.sha1().digest_size            # = tamanho em bytes da saída da função de hash
    k = math.ceil(n.bit_length()/8)                 # = comprimento em bytes do n

    if len(L) > 2**61 - 1: # Limite de 2^61 - 1 bytes da função de hash
        raise ValueError("Rótulo muito longo")
    elif len(M) > k - 2*h_len - 2: # Limite de k - 2hlen - 2 bytes da função de hash
        raise ValueError("Mensagem muito longa")
    else:  
        if L == None or L == b'' or L == '':
            L = b''

        lHash = hashlib.sha1(L).digest()            # lHash = H(L), onde L é o rótulo opcional
        PS = b'\x00' * (k - len(M) - 2*h_len - 2)       # PS = bytes de preenchimento de zero de comprimento k - mLen - 2hlen - 2    
        DB = lHash + PS + b'\x01' + M               # DB = lHash || PS || 0x01 || M

        seed = os.urandom(h_len)                    # seed = octeto aleatório de comprimento hLen
        db_mask = MGF(seed, k - h_len - 1)          # dbMask = MGF(seed, k - hLen - 1)
        masked_db = bytes(a ^ b for a, b in zip(DB, db_mask))   # maskedDB = DB \xor dbMask
        seed_mask = MGF(masked_db, h_len)           # seedMask = MGF(maskedDB, hLen)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        EM = b'\x00' + masked_seed + masked_db
        return EM

def encode(plainText):
    byte_message = plainText.encode('utf-8')                            # Converte a string para uma sequência de octetos usando UTF-8
    
    [n, e, d] = rsa_parameters()                                        # Gera os parâmetros do RSA
    print (f"n: {n}, e: {e}, d: {d}")

    k = math.ceil(n.bit_length()/8)                                     # k = tamanho do n em bytes
    
    L = b''                                                             # L = rótulo opcional
    rsa_oaep_message = rsa_oaep(n, e, byte_message, L, k)             # Codifica a mensagem usando RSA-OAEP
    #print ("Mensagem com Padding: ", rsa_oaep_message)
    
    int_padded_message = OS2IP(rsa_oaep_message)                        # Converte a mensagem codificada para inteiro
    #print ("Mensagem com Padding em inteiro: ", int_padded_message)

    c = (rsa_encode(int_padded_message, n, e))                          # Codifica a mensagem usando RSA
    #print (f"Mensagem codificada: {c}")
    C = I2OSP(c, k)                                                     # Converte a mensagem codificada para string de octetos (bytes)

    return C

def decode(C):
    pass

def main():
    plainText = "Hello Darkness my old friend"
    print ("Mensagem original: ", plainText)

    # Codifica a mensagem usando RSA-OAEP
    C = encode(plainText)
    print (f"Mensagem codificada: {bytes2string(C)}")

    # Decodifica a mensagem usando RSA-OAEP
    #M = decode(C)

if __name__ == "__main__":
    main()