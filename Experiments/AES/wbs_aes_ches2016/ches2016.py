from bucketing.core.aes import Bucketing


TRACES_ROOT_PATH = "./traces/"

bucket = Bucketing(TRACES_ROOT_PATH, start_s_box=0, end_s_box=1, decrypt=False, plot=True, verbose=True)

bucket.key_recovery()

