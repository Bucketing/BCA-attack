from time import time
import struct

from bucketing.utils.des_utils import read_trace_by_byte,\
    byte2bit, bit2byte_liste, bit2byte, perm_byte_list, perm_bit_list, get_sbox_index
from bucketing.utils.viewer import plot_data
from bucketing.utils.des_consts import SBOX, E, IP, FP


class Bucketing():

    def __init__(self,traces_root_path, start_s_box=0,
                 end_s_box=8, nb_traces=32, plot=False, verbose=False):
        self.verbose = verbose
        self.start_s_box = start_s_box
        self.end_s_box = end_s_box
        self.traces_root_path = traces_root_path
        self.nb_traces_per_set = nb_traces
        self.nb_samples = 0
        self.round_key = None
        self.master_key = None
        self.plot = plot
        self.inputs = []
        self.traces = []
        self.regrouped_traces = []
        self.__pre_computation()

    def __pre_computation(self):
        bit = 0  # the bucketing bit
        for s in range(0, self.end_s_box):
            s_traces = []
            s_inputs = []
            r0 = 32 * [0]
            path = self.traces_root_path + "/sbx_{}/".format(s)
            for x in range(64):
                for i, j in enumerate(E[6 * s:6 * s + 6]):
                    r0[j - 1] = byte2bit([x])[2:][i]
                s_inputs.append(perm_byte_list(4 * [0] + bit2byte_liste(r0), FP))
                s_traces.append(path + "trace_{}".format(x))
            self.inputs.append(s_inputs)
            self.traces.append(s_traces)
            buckets = []
            for g in range(64):
                sub_bucket = []
                for b in [0, 1]:
                    sub_sub_bucket = []
                    for i, p in enumerate(s_inputs):
                        exp_r0 = perm_bit_list(perm_bit_list(byte2bit(p), IP)[32:], E)
                        exp_r0_6 = bit2byte(exp_r0[6 * s: 6 * s + 6])
                        sbx_index = get_sbox_index(byte2bit([exp_r0_6 ^ g])[2:])
                        sbx_out = SBOX[s][sbx_index]
                        if ((sbx_out & (1 << bit)) >> bit) == b:
                            sub_sub_bucket.append(s_traces[i])
                    sub_bucket.append(sub_sub_bucket)
                buckets.append(sub_bucket)
            self.regrouped_traces.append(buckets)

    @staticmethod
    def read_trace(trace_name):
        return read_trace_by_byte(trace_name)

    def get_filter(self, current_s_box, g):
        filter_index = [i for i in range(self.nb_samples)]
        for i in range(self.nb_traces_per_set):
            t0 = self.read_trace(self.regrouped_traces[current_s_box][g][0][i])
            t1 = self.read_trace(self.regrouped_traces[current_s_box][g][1][i])
            filter_index = [j for j in filter_index if t0[j] != t1[j]]
        return filter_index

    @staticmethod
    def get_filtered_trace(file_name, filter_index):
        f = open(file_name, "rb")
        trace_data = []
        for i in filter_index:
            f.seek(i, 0)
            trace_data.append(struct.unpack("B", f.read(1))[0])
        f.close()
        return trace_data

    def get_filtered_ip0_ip1(self, filter_index, current_s_box, g):
        filtered_ip0, filtered_ip1 = [], []
        for i in range(self.nb_traces_per_set):
            filtered_ip0.append(self.get_filtered_trace(self.regrouped_traces[current_s_box][g][0][i], filter_index))
            filtered_ip1.append(self.get_filtered_trace(self.regrouped_traces[current_s_box][g][1][i], filter_index))
        return filtered_ip0, filtered_ip1

    @staticmethod
    def is_disjoint(v1, v2):
        return not any(set(v1).intersection(set(v2)))

    def guess_key_chunk(self, current_s_box):
        score = 64*[0]
        start_time = time()
        for g in range(64):
            start_filter_time = time()
            filter_index = self.get_filter(current_s_box, g)
            remain_samples = len(filter_index)
            ip0, ip1 = self.get_filtered_ip0_ip1(filter_index, current_s_box, g)
            for i in range(remain_samples):
                v1 = [ip0[j][i] for j in range(self.nb_traces_per_set // 2)]
                v2 = [ip1[j][i] for j in range(self.nb_traces_per_set // 2)]
                if self.is_disjoint(v1, v2):
                    score[g] += 1
                if self.verbose:
                    print("g: {} filter done in {} sc, {} samples remain, score = {}"
                          .format(hex(g), round(time() - start_filter_time, 5), remain_samples, score[g]))
        best = [i for i, j in enumerate(score) if j == max(score)][0]
        print("sbox-{}: best = {} with {} disjoint-vectors, time {} sec."
              .format(current_s_box, hex(best), score[best], round(time() - start_time, 3)))
        if self.plot:
            plot_data(score, x_label="6-bit guess")
        return best

    def round_key_recovery(self):
        print("start round key recovery ...")
        start_attack_time = time()
        self.nb_samples = len(self.read_trace(self.regrouped_traces[0][0][0][0]))  # update nb_samples
        if self.verbose:
            print("Number of simples per trace before filtering: {}.".format(self.nb_samples))
        self.round_key = 48*[0]
        for i in range(self.start_s_box, self.end_s_box):
            self.round_key[i * 6:i * 6 + 6] = byte2bit([self.guess_key_chunk(i)])[2:]
        print("recover round key done in  {} sc.".format(round(time() - start_attack_time, 3)))