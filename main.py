import random

number_of_bits = 1024

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

def binary2int(binary):
    n = 0
    pow2 = 1
    for i in range(len(binary)-1, -1, -1):
        n += binary[i] * pow2
        pow2 *= 2
    return n
    
def random_odd_value(number_of_bits):
    B = [0]*number_of_bits
    B[0] = 1
    B[-1] = 1
    for i in range(1, number_of_bits-1):
        B[i] = random.randint(0,1)
    return binary2int(B)

def generate_probable_prime(number_of_bits):
    while True:
        n = random_odd_value(number_of_bits)
        if (miller_rabin(n, 40)):
            return n

def main():
    p = generate_probable_prime(number_of_bits)
    q = generate_probable_prime(number_of_bits)
    print(p)
    print(q)

if __name__ == "__main__":
    main()