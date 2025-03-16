from Crypto.PublicKey import RSA
from sympy import factorint

def solve_rsa_problem(public_key_pem):
    """
    Solves the RSA factorization problem given the public key as a string.

    Args:
        public_key_pem (str): RSA public key in PEM format.

    Returns:
        tuple: The prime factors (p, q) of the RSA modulus n.
    """
    # Import the RSA public key
    key = RSA.importKey(public_key_pem)
    n, e = key.n, key.e

    # Factorize n using sympy
    factors = factorint(n)
    p, q = list(factors.keys())

    return p, q

def main():
    # Example public key as a string
    public_key_pem = """
    -----BEGIN PUBLIC KEY-----
    MDcwDQYJKoZIhvcNAQEBBQADJgAwIwIcB+14l4VT70lsgbSHTj2CzAXjbTnpmNMU
    odUAcwIDAQAB
    -----END PUBLIC KEY-----
    """
    # Solve for the prime factors of n
    p, q = solve_rsa_problem(public_key_pem)

    # Print the results
    print(f"Prime factors of n:\n p = {p}\n q = {q}")

if __name__ == "__main__":
    main()

