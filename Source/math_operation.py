


# Compute c = m^e mod n
def rsa_encrypt(
        m: int,
        e: int,
        n: int,
) -> int:
    return pow(m, e, n)


# Compute m = c^d mod n, with the help of CRT
def rsa_decrypt(
        c: int,
        n: int,
        p: int,
        q: int,
        dmp1: int,
        dmq1: int,
        iqmp: int,
) -> int:
    m_p = pow(c, dmp1, p)
    m_q = pow(c, dmq1, q)
    t1 = (m_p - m_q) % p
    t2 = (t1 * iqmp) % p
    m = (m_q + t2 * q) % n
    return m