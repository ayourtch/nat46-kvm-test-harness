# nat46-kvm-test-harness
A test harness to be run as /init under kvm to make testing easier

This is a WIP experiment to help testing of https://github.com/ayourtch/nat46/ - the current "CI" is very minimal, basically being "if it builds, ship it" - so this aims to add some functional testing, and since we are testing the kernel module, we need to be inside a VM.

The traditional route would have been probably to make a disk image of an existing OS, and then use that; but as an experiment I wanted to try what happens
if we collapse all the layers - and just have a single executable driving it all.

This is the repository of that single executable. The idea is to make it part of the initrd, such that the testing can be ultra-lightweight: no need to do filesystems, images, etc. etc.

## Packet capture

Start a JSONL capture with:

```text
capture start <interface> <file> [jsonl|pcap] [count] [include=nd] [ignore=arp]
```

`capture start` returns only after its packet socket is ready. Neighbor
Discovery traffic is excluded by default so routine address resolution does
not disturb packet-count assertions; use `include=nd` when testing ND itself.
The ND classification is limited to valid ICMPv6 types 133 through 137 with
code zero and hop limit 255. ARP remains captured unless `ignore=arp` is set.


