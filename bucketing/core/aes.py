from time import time
import struct

from bucketing.utils.aes_utils import reverse_key_schedule
from bucketing.utils.viewer import plot_data
from bucketing.utils.aes_utils import SBX, SBX_INV


class Bucketing():

    def __init__(self,
                 traces_root_path,
                 start_s_box=0,
                 end_s_box=16,
                 nb_traces=16,
                 plot=False,
                 decrypt=False,
                 verbose=False,
                 ):
        self.verbose = verbose
        self.start_s_box = start_s_box
        self.end_s_box = end_s_box
        self.traces_root_path = traces_root_path
        self.nb_traces_per_set = nb_traces
        self.decrypt = decrypt
        self.start_guess = 0
        self.end_guess = 256
        self.nb_samples = 0

        self.recovered_key = 16*[0]
        self.master_key = None
        self.plot = plot
        self.inputs = []
        self.traces = []
        self.regrouped_traces = []
        self.__pre_computation()

    def __pre_computation(self):
        sbx = SBX_INV if self.decrypt else SBX
        for s in range(0, self.end_s_box):
            s_traces = []
            s_inputs = []
            path = self.traces_root_path + "/sbx_{}/".format(s)
            for x in range(256):
                s_inputs.append([x if i == s else 0 for i in range(16)])
                s_traces.append(path + "trace_{}".format(x))
            self.inputs.append(s_inputs)
            self.traces.append(s_traces)
            buckets = []
            for g in range(256):
                sub_bucket = []
                for d in [0x0, 0xf]:
                    sub_sub_bucket = []
                    for i, p in enumerate(s_inputs):
                        if sbx[p[s] ^ g] & 0x0f == d:
                            sub_sub_bucket.append(s_traces[i])
                    sub_bucket.append(sub_sub_bucket)
                buckets.append(sub_bucket)
            self.regrouped_traces.append(buckets)

    @staticmethod
    def __read_trace(file_name):
        f = open(file_name, "rb")
        trace_data = []
        while True:
            e = f.read(1)
            if not e:
                break
            trace_data.append(struct.unpack("B", e)[0])
        f.close()
        return trace_data

    @staticmethod
    def __get_filtered_trace(file_name, filter_index):
        f = open(file_name, "rb")
        trace_data = []
        for i in filter_index:
            f.seek(i)
            trace_data.append(struct.unpack("B", f.read(1))[0])
        f.close()
        return trace_data

    def get_filtered_ip0_ip1(self, filter_index, current_s_box, g):
        filtered_ip0, filtered_ip1 = [], []
        for i in range(self.nb_traces_per_set):
            filtered_ip0.append(self.__get_filtered_trace(self.regrouped_traces[current_s_box][g][0][i], filter_index))
            filtered_ip1.append(self.__get_filtered_trace(self.regrouped_traces[current_s_box][g][1][i], filter_index))
        return filtered_ip0, filtered_ip1

    def get_filter(self, current_s_box, g):
        filter_index = [i for i in range(self.nb_samples)]
        for i in range(self.nb_traces_per_set):
            t0 = self.__read_trace(self.regrouped_traces[current_s_box][g][0][i])
            t1 = self.__read_trace(self.regrouped_traces[current_s_box][g][1][i])
            filter_index = [j for j in filter_index if t0[j] != t1[j]]
        return filter_index

    @staticmethod
    def is_disjoint_with_remove_consts(v1, v2):
        s1 = set(v1)
        s2 = set(v2)
        if len(s1) == 1 or len(s2) == 1:
            return False
        return not any(s1.intersection(s2))

    @staticmethod
    def is_disjoint(v1, v2):
        return not any(set(v1).intersection(set(v2)))

    def guess_key_chunk(self, current_s_box):
        score = 256*[0]
        start_time = time()
        print("target sbox-{} ...".format(current_s_box))
        for g in range(self.start_guess, self.end_guess):   # 0x10, 0x1f 0xd9, 0xf1
            start_filter_time = time()
            filter_index = self.get_filter(current_s_box, g)
            remain_samples = len(filter_index)
            ip0, ip1 = self.get_filtered_ip0_ip1(filter_index, current_s_box, g)
            for i in range(remain_samples):
                v1 = [ip0[j][i] for j in range(self.nb_traces_per_set)]
                v2 = [ip1[j][i] for j in range(self.nb_traces_per_set)]
                if self.is_disjoint(v1, v2):
                    score[g] += 1
            if self.verbose:
                print("g: {} filter done in {} sc, {} samples remain, score = {}"
                      .format(hex(g), round(time() - start_filter_time, 5), remain_samples, score[g]))
        best = [i for i, j in enumerate(score) if j == max(score)][0]
        print("sbox-{}: best = {} with {} disjoint-vectors, time {} sec."
              .format(current_s_box, hex(best), score[best], round(time() - start_time, 3)))
        if self.plot:
            plot_data(score)
        return best

    def key_recovery(self):
        print("start round key recovery ...")
        print("traces path: {}".format(self.traces_root_path))
        start_attack_time = time()
        self.nb_samples = len(self.__read_trace(self.regrouped_traces[self.start_s_box][self.start_guess][0][0]))
        if self.verbose:
            print("Number of simples per trace before filtering: {}.".format(self.nb_samples))
        for i in range(self.start_s_box, self.end_s_box):
            self.recovered_key[i] = self.guess_key_chunk(i)
        # if self.decrypt:
        #     self.recovered_key = reverse_key_schedule(self.recovered_key)
        self.master_key = reverse_key_schedule(self.recovered_key) if self.decrypt else self.recovered_key
        print("key recovery ({}) done in  {} sc.".
              format(bytes(self.master_key).hex(), round(time() - start_attack_time, 3)))
