import subprocess
import time

def get_sent_bytes():
    output = subprocess.check_output("ethtool -S eth2", shell=True).decode('utf-8')
    lines = output.split('\n')
    for line in lines:
        tokens = line.split(":")
        if len(tokens) < 2:
            continue
        key = tokens[0].strip()
        value = tokens[1].strip()
        if key == "tx_bytes":
            sent_bytes = int(value)
            print(line)
            return sent_bytes

interval = 5
prev_sent_bytes = get_sent_bytes()
while True:
    time.sleep(interval)
    curr_sent_bytes = get_sent_bytes()
    diff = curr_sent_bytes - prev_sent_bytes
    bandwidth = (diff / (1024 * 1024)) / interval
    print(f"Interface eth2, Bandwidth: {bandwidth:.2f} MBps")
    print("#"*20)
    prev_sent_bytes = curr_sent_bytes