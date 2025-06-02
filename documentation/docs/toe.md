# Analysis of TOE's Security Features

As described in the Chapter [Methodology](./methodology.md), the OpenStack Checker receives two inputs which are compared against each other:

* The *Concrete OpenStack Instance* representing the implementation of the Target of Evaluation (TOE).
* The *OpenStack Checker Configuration* containing the security goals, Concepts and Operations and "tagging" logic.

This Section describes how we model the Concrete OpenStack Instance in more detail and argues why it is suitable to provide an adequate and extensible description of the TOE's security features.

## The CPG

The Code Property Graph (CPG) is the central representation of the Concrete OpenStack Instance which is used for the analysis.
It is directly derived from the source code of the OpenStack components which contains the security features.
As OpenStack's security guarantees mostly depend on the concrete configuration of an instance, the configuration is loaded into the CPG as well.

Based on this input, the CPG generates an abstract graph representation of the code, starting from the abstract syntax tree (AST) of the source code and extending it with control flow and data flow information, among others.
The specification of the CPG is provided in its documentation [^1] and has been found to be suitable for the security analysis of large code bases [^2]. 

During the construction of the CPG, some unavailable information is added based on heuristics which may result in incorrect translations.
To make this visible to the user, the affected nodes and edges receive an assumption (see [Representation of Assumptions in the Analysis](toe.md#representation-of-assumptions-in-the-analysis)).

## Extensions for OpenStack

OpenStack's implementation provides several challenges for static analysis, which have been addressed by the OpenStack Checker:

### Modularization of the Code

The code of a concrete OpenStack instance is highly modularized, which allows for a flexible configuration of the instance, easy replacement of components, and a clear separation of concerns.
For the analysis, however, this modularization poses a challenge as the static analysis tools need to be able to analyze the code across module boundaries.
To address this issue, the CPG loads various modules of OpenStack at the same time and translates them into a single CPG.
In order to keep the architectural structure visible, the CPG holds one `Component` for each module.

The different modules interact with each other through HTTP APIs and calls.
To represent this, the OpenStack Checker aims to automatically detect the respective endpoints, the calls thereof.
The OpenStack Checker connects the calls with the endpoints across module boundaries and also includes dataflow edges across these boundaries.
This happens in custom passes which are implemented for the frameworks WSGI and Pecan, which are used in the OpenStack code base.

### Dynamic Loading of Modules

OpenStack dynamically loads modules at runtime based on the configuration of the instance, e.g. to load different drivers for different backends on the client side.
This results in code which is not statically known by only analyzing the source code but requires analysis of the configuration, and the loaded modules.
OpenStack provides these mechanisms in their own framework `stevedore` for which the OpenStack Checker implements another custom pass.
This pass analyzes the configuration of the OpenStack instance and loads the respective modules into the CPG and replaces function calls and variables with those loaded on runtime.
This is essential to ensure that the analysis is conducted on the code which resembles the actual OpenStack instance.
Failure to integrate the dynamically loaded modules would result in incomplete analysis and disconnecting the different modules from each other.
This would prevent the OpenStack Checker from analyzing the OpenStack instance as whole and miss the implementation of security features of the instance which are spread across different modules.

## Representation of Assumptions in the Analysis

As each static analysis tool makes certain assumptions about the code, it is important to express them for the user to enable verifying and understanding the results.
The OpenStack Checker requires the user to verify and accept these assumptions to retrieve a valid analysis result.
Each of the assumptions should contain a description of the assumption, together with a description of how to assess it.

This is crucial to improve the transparency of the analysis' limitations and trade-offs, thus making the results more understandable and trustworthy to the expert user.
The description assists the user to accept or reject the assumption, which, in turn, supports the reproducibility of the analysis outcome.
This also allows the user to invalidate results which are based on assumptions that do not hold for the analyzed code, thus preventing false acceptance of compliance with the security goals.

## Reproducibility of the Analysis

As the translation of the code into the CPG is performed automatically, the analysis is reproducible if this is the case for the algorithms applied for the translation.
The CPG is generated by first parsing the source code into an abstract syntax tree (AST) and then running several passes to enrich the graph.
To parse the AST, we use state-of-the-art parsers for the respective programming languages.

These may use certain heuristics to deal with incomplete or incorrect code, which may lead to different results and errors but since each run of the CPG uses the same heuristics, these can be reproduced.
As discussed above, we make these potential mistakes visible to the user by tagging the affected nodes and edges with an assumption.

The remaining passes should as well be deterministic and thus lead to reproducible results for the same input and configuration assuming that the implementations are correct.
Several of the passes are implemented as a fixed-point iteration, an established technique in static analysis to ensure that the analysis converges to a stable state.
These are also used in compilers, among others, and are very well understood.
We use this technique to create the data flow graph (DFG), control dependence graph (CDG), and to resolve symbols in the CPG.
Behind the scenes of the tagging DSL, and several passes used to add concepts and operations to the CPG, we also make use of the fixed-point iteration.

Note that some passes do not use a fixed-point iteration because they do not require control flow information or are executed before such information is available.
This includes the passes creating the type hierarchy and the evaluation order graph (EOG) as well as some of the custom passes adding concepts and operations based on symbol names.
These passes, however, only require the information of a single node (or multiple nodes but without assessing them in execution order), so that the result is deterministic as a simple rule is applied for each node in the graph.


[^1]: https://fraunhofer-aisec.github.io/cpg/CPG/specs/
[^2]: Yamaguchi, Fabian, et al. "Modeling and discovering vulnerabilities with code property graphs." 2014 IEEE Symposium on Security and Privacy (S&P). IEEE, 2014.
