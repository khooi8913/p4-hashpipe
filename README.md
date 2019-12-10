# HashPipe Algorithm P4_16 Implementation
This is the unofficial P4_16 implementation of the HashPipe algorithm proposed in, "Heavy-Hitter Detection Entirely in the Data Plane" at the Symposium of SDN Research (SOSR) 2017. [Link to paper](https://dl.acm.org/citation.cfm?id=3063772)

## Description
The implementation is adapted into the `basic` tutorial with basic IPv4 forwarding from SIGCOMM's 2019 P4 Tutorial session.

### Implementation Details
Brief info about the implemented specifications:
+ Number of stages, d = 2
+ Counters per stage, c = 1024
+ Hash functions used => CRC32
+ Target architecture => V1Model (BMv2)

