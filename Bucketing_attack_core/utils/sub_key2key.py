from Crypto.Cipher import DES as DES_REF

from bucketing.utils.des_utils import *
from bucketing.utils.des_consts import PC2, PC1

PC1_INV = invert_perm(PC1, 64)
PC2_INV = invert_perm(PC2, 56)


def invert_des_left_shift(in_key_bit_list, r):
    ls_table = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

    out_key_bit_list = 56 * [0]
    if ls_table[r] == 2:
        out_key_bit_list[2:28] = in_key_bit_list[:26]
        out_key_bit_list[0] = in_key_bit_list[26]
        out_key_bit_list[1] = in_key_bit_list[27]
        out_key_bit_list[30:] = in_key_bit_list[28:54]
        out_key_bit_list[28] = in_key_bit_list[54]
        out_key_bit_list[29] = in_key_bit_list[55]
    else:
        out_key_bit_list[1:28] = in_key_bit_list[:27]
        out_key_bit_list[0] = in_key_bit_list[27]
        out_key_bit_list[29:] = in_key_bit_list[28:55]
        out_key_bit_list[28] = in_key_bit_list[55]
    return out_key_bit_list


def invert_pc2(sub_key_bits, byte):
    pc2_inv_key_bits = perm_bit_list(sub_key_bits, PC2_INV)
    pc2_removed_bits = byte2bit([byte])
    for i, j in zip([9, 18, 22, 25, 35, 38, 43, 54], range(8)):
        pc2_inv_key_bits[i - 1] = pc2_removed_bits[j]
    return pc2_inv_key_bits


def invert_pc1(sub_key_bits):
    return perm_bit_list(sub_key_bits, PC1_INV)


def is_des_key(guess_key, in_plain, in_cipher, decrypt=None):
    des_verif = DES_REF.new(bytes(guess_key), DES_REF.MODE_ECB)
    encdec = des_verif.decrypt if decrypt else des_verif.encrypt
    cipher = encdec(bytes(in_plain))
    for pp, qq in zip(cipher, in_cipher):
        if pp != qq:
            return 0
    return 1


def invert_des_key_derivation(sub_key, sub_key_round, in_plain, cipher_ref, decrypt=None):
    """
    Generate all sixteen round subkeys
    """
    guess_key = 8 * [0]
    for x in range(256):
        inv_pc2_out = invert_pc2(byte2bit(sub_key), x)
        for i in range(sub_key_round):
            tmp = invert_des_left_shift(inv_pc2_out, i)
            inv_pc2_out = tmp
        inv_pc1_out = invert_pc1(inv_pc2_out)
        guess_key = bit2byte_liste(inv_pc1_out)
        if is_des_key(guess_key, in_plain, cipher_ref, decrypt) == 1:
            print("Key Recovery Success with PC2-brute-forced byte = 0x%02x" % x)
            return guess_key
    print("Key Recovery Failed")
    return guess_key

if __name__ == "__main__":
    k = [28, 3, 3, 36, 20, 2, 12, 7]
