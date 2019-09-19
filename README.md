# p4-hash-pipe-implementation
P4 implementation of the HashPipe algorithm proposed in the paper, "Heavy-Hitter Detection Entirely in the Data Plane" @ SOSR'17
[Link to paper] (https://dl.acm.org/citation.cfm?id=3063772)

### Note
> The implementation is adapted into the `basic` tutorial with basic IPv4 forwarding from the SIGCOMM 2019 P4 Tutorial session.

Brief info about the implemented specifications:
+ Number of stages, d = 2
+ Counters per stage, c = 1024
+ Hash functions used, CRC32
