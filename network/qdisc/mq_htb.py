import os

# Define the command to run for each file
htb_parent = "tc qdisc add dev eth2 parent {}  handle {}: htb default 4"
parent = "tc class add dev eth2 parent {}: classid {}:1 htb rate 200mbps ceil 1200mbps"
host = "tc class add dev eth2 parent {}:1 classid {}:3 htb rate 300mbps ceil 120000mbps"
default = "tc class add dev eth2 parent {}:1 classid {}:4 htb rate 900mbps ceil 1200mbps"
filter =  "tc filter add dev eth2 protocol ip parent {}:0 prio 1  u32 match ip src 10.96.4.85 flowid {}:3"


mqs = ["300:20", "300:1f", "300:1e", "300:1d", "300:1c", "300:1b", "300:1a", "300:19", "300:18", "300:17", "300:16", "300:15", "300:14", "300:13", "300:12", "300:11", "300:10", "300:f", "300:e", "300:d", "300:c", "300:b", "300:a", "300:9", "300:8", "300:7", "300:6", "300:5", "300:4", "300:3", "300:2", "300:1"]

os.system("tc qdisc del dev eth2 root mq")
os.system("tc qdisc add dev eth2 root handle 300: mq")

for major, parent_hdl in enumerate(mqs):
    major = major + 1
    htb_parent_cmd = htb_parent.format(parent_hdl, major)
    print(htb_parent_cmd)
    os.system(htb_parent_cmd)
    parent_cmd =  parent.format(major, major)
    print(parent_cmd)
    os.system(parent_cmd)
    host_cmd = host.format(major, major)
    print(host_cmd)
    os.system(host_cmd)
    default_cmd = default.format(major, major)
    print(default_cmd)
    os.system(default_cmd)
    filter_cmd  = filter.format(major, major)
    print(filter_cmd)
    os.system(filter_cmd)
