# Analysis of Security Promises

As described in the Chapter [Methodology](./methodology.md), the OpenStack Checker receives two inputs which are compared against each other:

* The *Concrete OpenStack Instance* representing the implementation of the Target of Evaluation (TOE).
* The *OpenStack Checker Configuration* containing the security goals, Concepts and Operations and "tagging" logic.

This Section describes how the OpenStack Checker Configuration in more detail and argues why it is suitable to provide an adequate and extensible description of the security goals.

## Description of Security Goals

The Security Goals are described by queries which are run against the CPG of the Concrete OpenStack Instance.
These queries include elements which require manual assessment, have the ability to express assumptions, and can be extended by the user.
The underlying Query API allows the user to evaluate simple values, but its main strength is the ability to track data and control flow across the TOE in a highly configurable way.
This can be leveraged to express several security goals and verify if violating paths exist in the code.
For all security goals which cannot be expressed by the Query API, the user can define custom checks which are then manually assessed.

## Reasoning about Program Semantics

The Security Goals are defined based on Concepts and Operations, whenever possible.
These serve to include semantic information in the program representation and allow the user to express high-level queries.
This is particularly useful as the queries representing the Security Goals can be written in a more abstract way, focusing on the security aspects rather than the implementation details.

The limitation to this are queries which aim to assess if the implementation of a security goal is correct, e.g., if a certain function is called with the correct parameters.
In this case, the query must include the implementation details or rely on correct tagging beforehand.

## Extensibility in Case of Changes

The Configuration itself is defined as Kotlin code and thus is highly flexible and extensible.
In particular, the main security goals/promises are represented as high-level queries which delegate required implementation details to Concepts and Operations or to parameters of the query.
This means, that updates in the TOE may either be reflected by changing the parameters of the query or by extending the tagging logic for Concepts and Operations.
The security goals themselves, however, do not need to be changed.
