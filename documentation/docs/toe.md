# Analysis of TOE's Security Features

As described in the Chapter [Methodology](./methodology.md), the OpenStack Checker receives two inputs which are compared against each other:

* The *Concrete OpenStack Instance* representing the implementation of the Target of Evaluation (TOE).
* The *OpenStack Checker Configuration* containing the security goals, Concepts and Operations and "tagging" logic.

This Section describes how we model the Concrete OpenStack Instance in more detail and argues why it is suitable to provide an adequate and extensible description of the TOE's security features.

## TODO: Description of the CPG

## TODO: Extensions for OpenStack

## Representation of Assumptions in the Analysis

As each static analysis tool makes certain assumptions about the code, it is important to express them for the user to enable verifying and understanding the results.
The OpenStack Checker requires the user to verify and accept these assumptions to retrieve a valid analysis result.
Each of the assumptions should contain a description of the assumption, together with a description of how to assess it.

