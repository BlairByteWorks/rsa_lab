#IMPORTING LIBRARIES
import random
import math
import time
import matplotlib.pyplot as plt

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm (Iterative version).
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def mod_inverse(e, phi):
    """
    Calculates the modular inverse of e mod phi using the
    Extended Euclidean Algorithm. (Replaces your brute-force search)
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        # This is mathematically impossible if e and phi are chosen correctly
        raise ValueError("Modular inverse does not exist")
    else:
        # x may be negative, so we add phi to make it positive
        return x % phi

def is_prime(n, k=10):
    """
    Miller-Rabin probabilistic primality test.
    (Replaces your inefficient trial-by-division test)

    k is the number of rounds, increasing k increases accuracy.
    10 rounds is more than enough for a lab.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d, where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop (k rounds)
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n) # x = a^d % n

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n) # x = x^2 % n
            if x == n - 1:
                break
        else:
            # If the loop finishes without x becoming n-1, n is composite
            return False

    # If all k rounds pass, n is probably prime
    return True

def generate_prime(min_value, max_value):
    """
    Generates a random prime number within a given range.
    (Modified to be more efficient and use the Miller-Rabin test)
    """
    # Ensure min_value is odd
    if min_value % 2 == 0:
        min_value += 1

    # Get a random odd number in the range
    prime = random.randrange(min_value, max_value + 1, 2)

    # Test for primality
    while not is_prime(prime):
        prime = random.randrange(min_value, max_value + 1, 2)
    return prime


print("--- RSA Demo (Small Keys) ---")
#ASSIGNING PRIME NUMBERS TO P AND Q, WITH CHECKS INCASE THEY ARE ASSIGNED THE SAME PRIME NUMBER
p, q = generate_prime(1000,5000), generate_prime(1000,5000)

while p == q:
    q = generate_prime(1000, 5000)

#CALCULATING N AND PHI OF N
n = p * q
phi_n = (p-1) * (q-1)

#CALCULATING E
e = random.randint(3, phi_n-1)
while math.gcd(e, phi_n) != 1:
    e = random.randint(3, phi_n - 1)

#CALCULATING D
d = mod_inverse(e, phi_n) # This now calls the fast Extended Euclidean Algorithm

print("Public key: ", e, ",", n)
print("p= ", p, "q= ", q)

message = input("Enter a message to be encrypted\n")
print("original message - ", message)

message_encoded = [ord(ch) for ch in message]

ciphertext = [pow(ch, e, n) for ch in message_encoded]

print("encrypted message - ", ciphertext)

message_encoded = [pow(ch, d, n) for ch in ciphertext]
message = "".join(chr(ch) for ch in message_encoded)

print("decrypted message - ", message)

#ANALYZING RSA PERFOMANCE
def analyze_rsa_performance():
    # Different key sizes in bits
    key_sizes = [1024, 2048, 3072, 4096, 5120]

    test_message = "RSA Performance Test"

    key_gen_times = []
    encryption_times = []
    decryption_times = []

    print("\n" + "="*20)
    print(" TIME REQUIREMENTS ANALYSIS")
    print("="*20)
    print("Analyzing time requirements for different key sizes...")
    print(f"Test message: '{test_message}'")
    print()

    for i, bits in enumerate(key_sizes, 1):
        print(f"Key Size {i} ({bits} bits):")

        # Calculate prime range for the desired bit size

        prime_bits = bits // 2
        min_val = 2**(prime_bits - 1)  # Minimum value for prime_bits
        max_val = 2**prime_bits - 1    # Maximum value for prime_bits

        # Time key generation
        start_time = time.time()
        # These calls now use the FAST generator and primality test
        p, q = generate_prime(min_val, max_val), generate_prime(min_val, max_val)
        while p == q:
            q = generate_prime(min_val, max_val)
        n = p * q
        phi_n = (p-1) * (q-1)
        e = random.randint(3, phi_n-1)
        while math.gcd(e, phi_n) != 1:
            e = random.randint(3, phi_n - 1)
        # This call now uses the FAST mod_inverse
        d = mod_inverse(e, phi_n)
        key_gen_time = time.time() - start_time

        # Time encryption
        start_time = time.time()
        message_encoded = [ord(ch) for ch in test_message]
        ciphertext = [pow(ch, e, n) for ch in message_encoded]
        encryption_time = time.time() - start_time

        # Time decryption
        start_time = time.time()
        message_encoded_decrypted = [pow(ch, d, n) for ch in ciphertext]
        decrypted_message = "".join(chr(ch) for ch in message_encoded_decrypted)
        decryption_time = time.time() - start_time

        key_gen_times.append(key_gen_time)
        encryption_times.append(encryption_time)
        decryption_times.append(decryption_time)

        print(f"  Key Generation: {key_gen_time:.4f} seconds")
        print(f"  Encryption: {encryption_time:.6f} seconds")
        print(f"  Decryption: {decryption_time:.6f} seconds")
        print(f"  Verification: {'✓' if decrypted_message == test_message else '✗'}")
        print()

    # Create graphical output
    key_size_labels = ['1024', '2048', '3072', '4096', '5120']

    plt.figure(figsize=(12, 8))

    # Plot 1: Key Generation Time
    plt.subplot(2, 2, 1)
    plt.plot(key_size_labels, key_gen_times, 'bo-', linewidth=2, markersize=8)
    plt.title('Key Generation Time vs Key Size')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.grid(True, alpha=0.3)

    # Plot 2: Encryption Time
    plt.subplot(2, 2, 2)
    plt.plot(key_size_labels, encryption_times, 'ro-', linewidth=2, markersize=8)
    plt.title('Encryption Time vs Key Size')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.grid(True, alpha=0.3)

    # Plot 3: Decryption Time
    plt.subplot(2, 2, 3)
    plt.plot(key_size_labels, decryption_times, 'go-', linewidth=2, markersize=8)
    plt.title('Decryption Time vs Key Size')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.grid(True, alpha=0.3)

    # Plot 4: All operations
    plt.subplot(2, 2, 4)
    plt.plot(key_size_labels, key_gen_times, 'bo-', label='Key Generation')
    plt.plot(key_size_labels, encryption_times, 'ro-', label='Encryption')
    plt.plot(key_size_labels, decryption_times, 'go-', label='Decryption')
    plt.title('All Operations vs Key Size')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.legend()
    plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('rsa_performance_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()

    print("Performance analysis complete!")
    print("Graph saved as 'rsa_performance_analysis.png'")

# Calling your analysis function at the end
analyze_rsa_performance()