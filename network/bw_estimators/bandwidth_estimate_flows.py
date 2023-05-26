import subprocess
import time

def get_sent_bytes():
    output = subprocess.check_output("tc -s -d class show dev eth2", shell=True).decode('utf-8')
    lines = output.split('\n')
    sent_bytes = {}
    last_line = ""
    for line in lines:
        if 'htb' in last_line and 'Sent' in line:
            class_id = last_line.split()[2]
            sent = int(line.split('Sent ')[1].split()[0])
            sent_bytes[class_id] = sent
        last_line = line
    return sent_bytes

interval = 5
prev_sent_bytes = get_sent_bytes()
while True:
    time.sleep(interval)
    curr_sent_bytes = get_sent_bytes()
    for class_id in curr_sent_bytes:
        diff = curr_sent_bytes[class_id] - prev_sent_bytes[class_id]
        bandwidth = (diff / (1024 * 1024)) / interval
        print(f"Class: {class_id}, Bandwidth: {bandwidth:.2f} MBps")
    print()
    prev_sent_bytes = curr_sent_bytes