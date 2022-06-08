#
# gen_rijndael_t_table.py - Generate Rijndael T-Table
#
# Non-Copyright (CC0) 2020 Free Software Initiative of Japan
# Author: NIIBE Yutaka <gniibe@fsij.org>
#
# This file is made available under the Creative Commons CC0 1.0
# Universal Public Domain Dedication.
#
# To the extent possible under law, the person who associated CC0 with
# this work has waived all copyright and related or neighboring rights
# to this work.
#

#
# Generate Rijindael T-Table (the first one) in the format
# of Mbed TLS (originally callled PolarSSL, by Paul Bakker).
#

# Rijndael uses GF(2^8) with a irreducible polynomial:
#
#   m(x) = x^8 + x^4 + x^3 + x + 1
#
# A point in the field is represented by 8-bit binary.

# 0x1b represents a lower part of m(x), x^4 + x^3 + x + 1
m_irreducible = 0x1b

# The constant
C = 0x63

# Function XTIME - Multiplication by x
#
# Given a polynomial A of GF(2)[x], compute a polynomial multiplied by x,
# modulo m(x).
def xtime(a):
    global m_irreducible
    if a & 0x80:
        return ((a & 0x7f) << 1) ^ m_irreducible
    else:
        return a << 1

# Function GMULT - Galore field multiplication
#
# Given polynomials A, B of GF(2)[x], compute a polynomial A * B,
# modulo m(x).
def gmult(a,b):
    r = 0
    for i in range(8):
        r = r ^ ((b & 0x01) * a)
        b = b >> 1
        a = xtime(a)
    return r

# Function INV - Multiplicative inverse
#
# Given polynomials A of GF(2)[x], compute its multiplicative inverse.
#
# Extended to have defined value at A=0, returning 0.
#
# Note about the implementation:
#
# Brute force appoarch finding an inverse is more efficient.  Further,
# for efficiency, using two tables of exp and log (with any good base
# like 3, 5, 6...) to compute exp(log(1) - log(a)) is much better,
# when called many times.
#
def inv(a):
    r = 1
    for i in range(254):        # 254 = 2^8 - 2
        r = gmult(r,a)
    return r

# Circular shift operation
def rotate(a,n):
    return ((a << n) & 0xff) | (a >> (8 - n))

def rijndael_affine_transform(v):
    global C
    return v ^ rotate(v,1) ^ rotate(v,2) ^ rotate(v,3) ^ rotate(v,4) ^ C

def sbox_value(i):
    return rijndael_affine_transform(inv(i))


def print_t_table_value(i,x):
    y = xtime(x)
    z = x ^ y
    punct = "" if i==255 else ", \\\n  " if i % 4 == 3 else ", "
    print("V(","%02X," % z,"%02X," % x,"%02X," % x,"%02X)" % y,
          punct, sep='', end='')

if __name__ == '__main__':
  #
  # Usage:
  #  $ python3 gen_rijndael_t_table.py
  #
  # Usage with args, replacing the irreducible and the constant:
  #  $ python3 gen_rijndael_t_table.py 1b 63
  #
  # Usage to generate Rcon
  #  $ python3 gen_rijndael_t_table.py 'Rcon[10]'
  #
  #  $ python3 gen_rijndael_t_table.py 1b 63 'Rcon[10]'
  #
  name_rcon = None

  import sys
  if len(sys.argv) == 2:
      name_rcon = sys.argv[1]
  elif len(sys.argv) >= 3:
      m_irreducible = int(sys.argv[1],16)
      C = int(sys.argv[2],16)
      if len(sys.argv) == 4:
          name_rcon = sys.argv[3]

  if name_rcon:
      n_rcon = int(name_rcon[name_rcon.index('[')+1:name_rcon.index(']')])
      print("static const uint32_t %s =\n{" % name_rcon)
      x = 1
      print(" ", end='')
      for i in range(n_rcon):
          punct = "\n" if i==n_rcon-1 else ",\n " if i % 4 == 3 else ", "
          print("0x%08X" % x, punct, sep='', end='')
          x = xtime(x)
      print("};")
      exit(0)

  # Note: I just want to use list comprehension of Python, though not needed
  S_box=[sbox_value(i) for i in range(256)]

  print("#define FT                                                        \\")
  print("  ", end='')
  for i in range(256):
      x = S_box[i]
      print_t_table_value(i,x)
  print("")
