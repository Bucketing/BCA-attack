from bucketing.core.des import Bucketing

TRACES_ROOT_PATH = "./traces"

bucket = Bucketing(TRACES_ROOT_PATH, start_s_box=0, end_s_box=1, plot=True, verbose=True)

bucket.round_key_recovery()


