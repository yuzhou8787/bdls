# BDLS Consensus

## Introduction

This library implements Sperax Byzantine Fault Tolerance in Partially Connected Asynchronous
Networks based on https://eprint.iacr.org/2019/1460.pdf.

To make the runtime behavior of consensus algorithm predictable, as a function:
y = f(x, t), where 'x' is the message it received, and 't' is the time while being called,
and 'y' is the deterministic status of consensus after 'x' and 't' applied to 'f',
this library has been designed in a deterministic scheme, without parallel
computing, networking, and current time is a parameter to this library.

As it's a pure algorithm implementation, it's not thread-safe! Users of this library
should take care of their own synchronization mechanism.

## Features

1. Pure algorithm implementation in deterministic and predictable behavior.
2. Well-tested on various platform.
3. Auto back-off under heavy payload, guaranteed finalization.
4. Easy to use in Blockchain consensus or non-Blockchain consensus, like database replication.
5. Builtin network emulation for various network latency.

## Documentation

For complete documentation, see the associated [Godoc](https://pkg.go.dev/github.com/Sperax/bdls).

## Benchmark

OS: 

```
$ uname -a
Linux DESKTOP-7FL7RC4 4.19.84-microsoft-standard #1 SMP Wed Nov 13 11:44:37 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

$ cat /proc/cpuinfo
processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 8
model name      : AMD Ryzen 7 2700X Eight-Core Processor
stepping        : 2
microcode       : 0xffffffff
cpu MHz         : 3693.112
cache size      : 512 KB
physical id     : 0
siblings        : 16
core id         : 0
cpu cores       : 8
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext
fxsr_opt pdpe1gb rdtscp lm rep_good nopl cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c 
rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext ssbd ibpb vmmcall fsgsbase bmi1 avx2 
smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 xsaves clzero xsaveerptr virt_ssbd arat
bugs            : sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass
bogomips        : 7386.22
TLB size        : 2560 4K pages
clflush size    : 64
cache_alignment : 64
address sizes   : 48 bits physical, 48 bits virtual
power management:

...（other 15 cores)

```



```
TERMINOLOGY: 

DECIDE.AVG = Average finalization time for each height.
DECIDE.ROUNDS = The rounds where a decide has made.
PEER.NUM = Actual participantion.
PJ.NUM = Participants(Quorum) 
NET.MSGS = Total network number of messages exchanged in all heights.
NET.BYTES = Total network bytes exchanged in all heights.
MSG.AVGSIZE = Average message size.(Tested with 1KB State.)
NET.MSGRATE = Network message rate(messages/second).
PEER.RATE = Peer's average bandwidth.
DELAY.MIN = Actual minimal network latency(network latency is randomized with normal distribution).
DELAY.MAX = Actual maximal network latency.
DELAY.AVG = Actual average latency.
DELAY.EXP = Expected Latency set to consensus algorithm.

TESTING CASES:
=============

Case 1: 20 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 1.48s      | 1;1;1;1;1     | 20       | 20     | 9780     | 16.2M     | 1.7K        | 65.88/s     | 110.1K/s  | 64.07ms   | 136.61ms  | 99.89ms   | 100ms     |
| 2.28s      | 1;1;1;1;1     | 20       | 20     | 9760     | 16M       | 1.7K        | 42.74/s     | 70.2K/s   | 118.6ms   | 273.75ms  | 200.21ms  | 200ms     |
| 3.11s      | 1;1;1;1;1     | 20       | 20     | 9756     | 16.1M     | 1.7K        | 31.33/s     | 51.6K/s   | 200.78ms  | 411.67ms  | 300.34ms  | 300ms     |
| 4.71s      | 1;1;1;1;1     | 20       | 20     | 9754     | 15.9M     | 1.7K        | 20.67/s     | 33.4K/s   | 242.75ms  | 694.62ms  | 499.74ms  | 500ms     |
| 8.9s       | 1;1;1;1;1     | 20       | 20     | 9753     | 15.8M     | 1.7K        | 10.95/s     | 17.7K/s   | 534.7ms   | 1.38039s  | 999.68ms  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 2: 30 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 1.53s      | 1;1;1;1;1     | 30       | 30     | 22148    | 36.6M     | 1.7K        | 96.17/s     | 158.7K/s  | 61.12ms   | 139ms     | 99.94ms   | 100ms     |
| 2.33s      | 1;1;1;1;1     | 30       | 30     | 22150    | 36.3M     | 1.7K        | 63.28/s     | 104.2K/s  | 125.44ms  | 271.17ms  | 200.09ms  | 200ms     |
| 3.13s      | 1;1;1;1;1     | 30       | 30     | 22143    | 36.2M     | 1.7K        | 47.09/s     | 77K/s     | 177.91ms  | 431.24ms  | 299.77ms  | 300ms     |
| 4.77s      | 1;1;1;1;1     | 30       | 30     | 22137    | 36.1M     | 1.7K        | 30.89/s     | 50.3K/s   | 293ms     | 696.15ms  | 499.78ms  | 500ms     |
| 8.91s      | 1;1;1;1;1     | 30       | 30     | 22136    | 35.9M     | 1.7K        | 16.56/s     | 26.9K/s   | 575.02ms  | 1.41643s  | 999.82ms  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 3: 50 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 1.75s      | 1;1;1;1;1     | 50       | 50     | 60570    | 107.4M    | 1.8K        | 138.11/s    | 242.5K/s  | 60.95ms   | 145.92ms  | 99.88ms   | 100ms     |
| 2.52s      | 1;1;1;1;1     | 50       | 50     | 61951    | 102.8M    | 1.7K        | 98.11/s     | 161.1K/s  | 106.85ms  | 277.12ms  | 199.85ms  | 200ms     |
| 3.38s      | 1;1;1;1;1     | 50       | 50     | 61909    | 101.5M    | 1.7K        | 73.17/s     | 118.4K/s  | 171.53ms  | 436.91ms  | 300.13ms  | 300ms     |
| 4.9s       | 1;1;1;1;1     | 50       | 50     | 61913    | 101.9M    | 1.7K        | 50.46/s     | 82.9K/s   | 283.81ms  | 711.21ms  | 500.04ms  | 500ms     |
| 8.96s      | 1;1;1;1;1     | 50       | 50     | 61907    | 101.5M    | 1.7K        | 27.63/s     | 45.2K/s   | 574.59ms  | 1.44652s  | 999.8ms   | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 4: 80 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 6.03s      | 2;2;2;2;2     | 80       | 80     | 289043   | 1.9G      | 6.8K        | 119.67/s    | 807.6K/s  | 54.12ms   | 146.16ms  | 99.95ms   | 100ms     |
| 3.99s      | 2;1;1;1;1     | 80       | 80     | 181935   | 690.8M    | 3.9K        | 113.84/s    | 430.2K/s  | 108.45ms  | 290.52ms  | 199.9ms   | 200ms     |
| 3.82s      | 1;1;1;1;1     | 80       | 80     | 155702   | 259.4M    | 1.7K        | 101.76/s    | 167K/s    | 167.5ms   | 427.37ms  | 299.93ms  | 300ms     |
| 5.35s      | 1;1;1;1;1     | 80       | 80     | 158150   | 262M      | 1.7K        | 73.89/s     | 120.2K/s  | 272ms     | 708.43ms  | 500.01ms  | 500ms     |
| 9.29s      | 1;1;1;1;1     | 80       | 80     | 159059   | 261.5M    | 1.7K        | 42.79/s     | 69.6K/s   | 577.08ms  | 1.42688s  | 999.7ms   | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 5: 100 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 7.56s      | 2;2;2;2;2     | 100      | 100    | 482524   | 2.3G      | 5K          | 127.50/s    | 634.6K/s  | 53.43ms   | 145.98ms  | 99.91ms   | 100ms     |
| 9.18s      | 1;2;2;2;1     | 100      | 100    | 383726   | 2.9G      | 7.8K        | 83.57/s     | 634.9K/s  | 108.32ms  | 294.75ms  | 199.9ms   | 200ms     |
| 4.28s      | 1;1;1;1;1     | 100      | 100    | 240392   | 403.5M    | 1.7K        | 112.09/s    | 185.3K/s  | 153.69ms  | 439.15ms  | 299.84ms  | 300ms     |
| 5.71s      | 1;1;1;1;1     | 100      | 100    | 244297   | 405.3M    | 1.7K        | 85.44/s     | 138.7K/s  | 290.1ms   | 714.57ms  | 499.92ms  | 500ms     |
| 9.69s      | 1;1;1;1;1     | 100      | 100    | 248828   | 408.7M    | 1.7K        | 51.34/s     | 83.4K/s   | 566.73ms  | 1.4509s   | 999.78ms  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+


Case 6: 20 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 3.1s       | 1;3;1;2;2     | 13       | 20     | 5328     | 8.6M      | 1.7K        | 26.42/s     | 43.2K/s   | 64.44ms   | 133.11ms  | 100ms     | 100ms     |
| 6.86s      | 4;1;1;1;3     | 13       | 20     | 5640     | 8.9M      | 1.6K        | 12.64/s     | 20.4K/s   | 119.57ms  | 266.59ms  | 199.84ms  | 200ms     |
| 5.4s       | 1;2;1;1;2     | 13       | 20     | 4704     | 7.9M      | 1.7K        | 13.39/s     | 22.7K/s   | 188.85ms  | 408.61ms  | 299.94ms  | 300ms     |
| 20.09s     | 3;3;2;2;3     | 13       | 20     | 6576     | 10M       | 1.6K        | 5.03/s      | 7.8K/s    | 267.96ms  | 682.36ms  | 500.22ms  | 500ms     |
| 42.55s     | 5;1;2;3;1     | 13       | 20     | 6264     | 9.6M      | 1.6K        | 2.26/s      | 3.5K/s    | 628.98ms  | 1.3668s   | 1.0001s   | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 7: 30 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 2.56s      | 1;1;1;1;3     | 20       | 30     | 11303    | 18.9M     | 1.7K        | 44.14/s     | 75K/s     | 64.29ms   | 135.73ms  | 100.17ms  | 100ms     |
| 6.53s      | 1;1;3;2;3     | 20       | 30     | 13582    | 21.4M     | 1.6K        | 20.77/s     | 33.4K/s   | 119.9ms   | 273.24ms  | 200.01ms  | 200ms     |
| 9.44s      | 2;4;1;2;1     | 20       | 30     | 13582    | 21.4M     | 1.6K        | 14.38/s     | 23.1K/s   | 173.41ms  | 422.81ms  | 299.73ms  | 300ms     |
| 7.6s       | 1;1;2;1;1     | 20       | 30     | 10544    | 18M       | 1.7K        | 13.86/s     | 23.9K/s   | 323.71ms  | 692.15ms  | 499.93ms  | 500ms     |
| 18.06s     | 3;1;1;1;1     | 20       | 30     | 11301    | 18.8M     | 1.7K        | 6.26/s      | 10.5K/s   | 656.16ms  | 1.37391s  | 1.00022s  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 8: 50 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 3.17s      | 1;1;2;3;2     | 33       | 50     | 35596    | 59.2M     | 1.7K        | 68.05/s     | 114K/s    | 60.64ms   | 146.65ms  | 100.06ms  | 100ms     |
| 6.69s      | 1;4;2;2;1     | 33       | 50     | 37440    | 59.7M     | 1.6K        | 33.92/s     | 54.8K/s   | 115.35ms  | 288.66ms  | 199.98ms  | 200ms     |
| 9.4s       | 1;2;3;3;1     | 33       | 50     | 37440    | 59.7M     | 1.6K        | 24.12/s     | 39.1K/s   | 181.03ms  | 420.03ms  | 299.91ms  | 300ms     |
| 12.21s     | 1;2;2;2;2     | 33       | 50     | 35328    | 57.3M     | 1.7K        | 17.52/s     | 28.8K/s   | 285.64ms  | 709.59ms  | 500.03ms  | 500ms     |
| 31.14s     | 1;1;4;2;2     | 33       | 50     | 37440    | 59.7M     | 1.6K        | 7.29/s      | 11.8K/s   | 609.91ms  | 1.37759s  | 999ms     | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 9: 80 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 6.52s      | 4;3;2;2;3     | 53       | 80     | 136838   | 700.3M    | 5.2K        | 79.12/s     | 410.3K/s  | 55.72ms   | 145.67ms  | 99.94ms   | 100ms     |
| 7.63s      | 1;5;1;1;1     | 53       | 80     | 91818    | 154.5M    | 1.7K        | 45.37/s     | 77.1K/s   | 113.3ms   | 289.44ms  | 199.95ms  | 200ms     |
| 7.26s      | 2;1;1;2;2     | 53       | 80     | 86229    | 143.6M    | 1.7K        | 44.76/s     | 75K/s     | 169.04ms  | 428.69ms  | 300.02ms  | 300ms     |
| 25.49s     | 1;3;4;1;4     | 53       | 80     | 113776   | 173.7M    | 1.6K        | 16.84/s     | 26.1K/s   | 296.99ms  | 710.86ms  | 499.78ms  | 500ms     |
| 17.71s     | 2;1;1;2;1     | 53       | 80     | 80704    | 136.7M    | 1.7K        | 17.19/s     | 29.4K/s   | 526.89ms  | 1.45599s  | 1.00015s  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 10: 100 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s correctly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 8.16s      | 3;3;3;4;3     | 67       | 100    | 256699   | 1.4G      | 5.5K        | 93.88/s     | 514K/s    | 57.42ms   | 145.84ms  | 99.98ms   | 100ms     |
| 7.07s      | 1;2;2;2;3     | 67       | 100    | 156050   | 271.1M    | 1.8K        | 65.86/s     | 114.3K/s  | 95.74ms   | 283.55ms  | 199.93ms  | 200ms     |
| 8.91s      | 2;1;2;1;3     | 67       | 100    | 147071   | 250.7M    | 1.7K        | 49.25/s     | 84K/s     | 168.85ms  | 447.5ms   | 299.81ms  | 300ms     |
| 9.79s      | 1;1;2;1;2     | 67       | 100    | 129232   | 219.3M    | 1.7K        | 39.39/s     | 67.2K/s   | 288.65ms  | 707.51ms  | 500.07ms  | 500ms     |
| 42.55s     | 1;3;4;1;3     | 67       | 100    | 173448   | 268.5M    | 1.6K        | 12.17/s     | 19.1K/s   | 559.28ms  | 1.4488s   | 1.00027s  | 1s        |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 11: 50 Fully Connected Participants in 100ms,200ms,300ms,500ms,1s incorrectly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 2.79s      | 2;2;2;2;2     | 50       | 50     | 117075   | 464.9M    | 4.1K        | 167.40/s    | 664.4K/s  | 56.91ms   | 147.22ms  | 100ms     | 50ms      |
| 3.33s      | 2;2;1;1;2     | 50       | 50     | 95144    | 260.6M    | 2.8K        | 114.29/s    | 307.5K/s  | 118.64ms  | 282.44ms  | 199.79ms  | 100ms     |
| 3.06s      | 1;1;1;1;1     | 50       | 50     | 73228    | 115.8M    | 1.6K        | 95.67/s     | 149.8K/s  | 168.55ms  | 425.94ms  | 300.08ms  | 150ms     |
| 4.4s       | 1;1;1;1;1     | 50       | 50     | 73523    | 114.7M    | 1.6K        | 66.70/s     | 103.6K/s  | 289.96ms  | 740.22ms  | 499.93ms  | 250ms     |
| 7.99s      | 1;1;1;1;1     | 50       | 50     | 73518    | 114.1M    | 1.6K        | 36.76/s     | 56.9K/s   | 574.08ms  | 1.44592s  | 1.00028s  | 500ms     |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+

Case 12: 50 Partially Connected Participants in 100ms,200ms,300ms,500ms,1s incorrectly set expected delay
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| DECIDE.AVG | DECIDE.ROUNDS | PEER.NUM | PJ.NUM | NET.MSGS | NET.BYTES | MSG.AVGSIZE | NET.MSGRATE | PEER.RATE | DELAY.MIN | DELAY.MAX | DELAY.AVG | DELAY.EXP |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
| 5.14s      | 4;3;3;4;5     | 33       | 50     | 67470    | 216.3M    | 3.3K        | 79.47/s     | 257.6K/s  | 57.58ms   | 143.66ms  | 99.98ms   | 50ms      |
| 4.31s      | 4;1;1;1;2     | 33       | 50     | 47131    | 232.2M    | 5K          | 66.12/s     | 326K/s    | 124.97ms  | 281.24ms  | 199.92ms  | 100ms     |
| 8.6s       | 1;1;4;4;3     | 33       | 50     | 49056    | 72.7M     | 1.5K        | 34.54/s     | 52K/s     | 178.53ms  | 425.98ms  | 299.92ms  | 150ms     |
| 10.46s     | 1;3;2;2;3     | 33       | 50     | 44832    | 67.9M     | 1.6K        | 25.97/s     | 39.9K/s   | 243.1ms   | 697.25ms  | 500.03ms  | 250ms     |
| 15.78s     | 3;1;1;1;2     | 33       | 50     | 38496    | 60.8M     | 1.6K        | 14.78/s     | 23.6K/s   | 531.72ms  | 1.39627s  | 1.00002s  | 500ms     |
+------------+---------------+----------+--------+----------+-----------+-------------+-------------+-----------+-----------+-----------+-----------+-----------+
```

## Specification

1. Consensus messages are specified in [message.proto](message.proto), users of this library can encapsulate this message in a carrier message, like gossip in TCP.
2. Consensus algorithm is NOT thread-safe, it MUST be protected by some synchronization mechanism, like `sync.Mutex` or `chan` + `goroutine`.

## Usage

1. A testing peer -- [ipc_peer.go](ipc_peer.go)
2. A testing tcp node

## Status

Alpha
