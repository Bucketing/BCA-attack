#!/usr/bin/python3
from random import randint
import struct

from bucketing.utils.des_consts import *


def get_random_bytes(nbr):
    return [randint(0, 255) for _ in range(nbr)]


def invert_perm(perm, size):
    inv = size*[0]
    n = len(perm)
    for i in range(n):
        inv[perm[i]-1] = i+1
    return inv


def bit2byte_liste(bit_list):
    return [int("".join(map(str, bit_list[i * 8:i * 8 + 8])), 2) for i in range(len(bit_list) // 8)]


def bit2byte(bit_list):
    return int("".join(map(str, bit_list)), 2)


def byte2bit(byte_list):
    return [(byte_list[i // 8] >> (7 - (i % 8))) & 0x01 for i in range(8 * len(byte_list))]


def perm_bit_list(input_bit_list, perm_table):
    return [input_bit_list[ee - 1] for ee in perm_table]


def perm_byte_list(in_byte_list, perm_table):
    out_byte_list = (len(perm_table) >> 3) * [0]
    for index, elem in enumerate(perm_table):
        i = index % 8
        t = (elem - 1) % 8
        if i >= t:
            out_byte_list[index >> 3] |= \
                (in_byte_list[(elem - 1) >> 3] & (128 >> t)) >> (i - t)
        else:
            out_byte_list[index >> 3] |= \
                (in_byte_list[(elem - 1) >> 3] & (128 >> t)) << (t - i)
    return out_byte_list


def get_sbox_index(in_bit_list):
    return (in_bit_list[0] << 5) + (in_bit_list[1] << 3) + \
           (in_bit_list[2] << 2) + (in_bit_list[3] << 1) + \
           (in_bit_list[4] << 0) + (in_bit_list[5] << 4)


def split_states(states):
    splited_states = []
    for s in states:
        for e in s:
            splited_states.append(e)
    return splited_states


def des_left_shift(in_key_bit_list, current_round):

    ls_table = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    out_key_bit_list = 56 * [0]
    if ls_table[current_round] == 2:
        out_key_bit_list[:26] = in_key_bit_list[2:28]
        out_key_bit_list[26] = in_key_bit_list[0]
        out_key_bit_list[27] = in_key_bit_list[1]
        out_key_bit_list[28:54] = in_key_bit_list[30:]
        out_key_bit_list[54] = in_key_bit_list[28]
        out_key_bit_list[55] = in_key_bit_list[29]
    else:
        out_key_bit_list[:27] = in_key_bit_list[1:28]
        out_key_bit_list[27] = in_key_bit_list[0]
        out_key_bit_list[28:55] = in_key_bit_list[29:]
        out_key_bit_list[55] = in_key_bit_list[28]
    return out_key_bit_list


def get_des_sub_key(key, rnd):
    sub_key_list = 16 * [[None] * 8]
    perm__key_bit_list = perm_bit_list(byte2bit(key), PC1)
    for r in range(16):
        aux_bit_list = des_left_shift(perm__key_bit_list, r)
        sub_key_list[r] = bit2byte_liste(perm_bit_list(aux_bit_list, PC2))
        perm__key_bit_list = aux_bit_list

    return sub_key_list[rnd]


def get_6bits_key_ref(known_key, sbx_indx):
    return bit2byte(byte2bit(get_des_sub_key(known_key, 0))[sbx_indx*6: sbx_indx*6 + 6])


def write_trace(trace_data, file_name):
    f = open(file_name, "wb")
    for e in trace_data:
        f.write(struct.pack("<I", e))
    f.close()


def read_trace_until(file_name, until=None):
    f = open(file_name, "rb")
    trace_data = []
    count = 0
    while True:
        e = f.read(4)
        if not e:
            break
        if until:
            if count >= until:
                break
            count += 1
        trace_data.append(struct.unpack("<I", e)[0])
    f.close()
    return trace_data


def read_trace_by_bytes_until(file_name, until=None):
    f = open(file_name, "rb")
    trace_data = []
    count = 0
    while True:
        e = f.read(1)
        if not e:
            break
        if until:
            if count >= until:
                break
            count += 1
        trace_data.append(struct.unpack("B", e)[0])
    f.close()
    return trace_data


def read_trace(file_name):
    f = open(file_name, "rb")
    trace_data = []
    while True:
        e = f.read(4)
        if not e:
            break
        trace_data.append(struct.unpack("<I", e)[0])
    f.close()
    return trace_data


def write_trace_by_byte(trace_data, file_name):
    f = open(file_name, "wb")
    for e in trace_data:
        f.write(struct.pack("B", e))
    f.close()


def read_trace_by_byte(file_name):
    f = open(file_name, "rb")
    trace_data = []
    while True:
        e = f.read(1)
        if not e:
            break
        trace_data.append(struct.unpack("B", e)[0])
    f.close()
    return trace_data


if __name__ == "__main__":

    test_data = [randint(0, 0xffffffff) for __ in range(100)]
    test_data_bytes = [e & 0x000000ff for e in test_data]
    print([hex(e) for e in test_data])
    print([hex(e) for e in test_data_bytes])
    test_file = "./test_trace"
    write_trace_by_byte(test_data_bytes, test_file)
    data = read_trace_by_byte(test_file)
    print(len(data))
    print([hex(e) for e in data])
