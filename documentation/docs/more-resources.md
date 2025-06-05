# Where to find...

## the code of the Query API?

The Query API is documented under the following page: [https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/](https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/)

The Query API is mostly defined in three files in the module `cpg-analysis`:

* `Query.kt`
* `FlowQueries.kt`
* `QueryTree.kt`

!!! note "The QueryTree object"

    A `QueryTree` serves as a wrapper around the results and the sub-statements which were used to retrieve the result.
    It also contains the assumptions which were collected on evaluation and a human-readable string representation.

## detailed information on the CPG?

Extensive documentation on the Code Property Graph (CPG) can be found online:

* [The specification of the graph schema (all nodes, their properties and edges)](https://fraunhofer-aisec.github.io/cpg/CPG/specs/graph/)
* [The specification of the dataflow graph (DFG)](https://fraunhofer-aisec.github.io/cpg/CPG/specs/dfg/)
* [The specification of the evaluation order graph (EOG)](https://fraunhofer-aisec.github.io/cpg/CPG/specs/eog/)

!!! note "Edges of Sub-Graphs"

    The sub-graphs are not transitive, i.e., if a node A is connected to a node B, and B is connected to C, then A is not necessarily connected to C via a direct edge.
    It is therefore recommended to use the functions traversing the graph (e.g. `dataFlow`, and `executionPath`) to traverse the graph instead of using the edges directly.

## `Concept`s and `Operation`s?

We provide a list of current concepts and operations [here](list-concepts-and-operations.md).
To generate/update this list, you can run the program `de.fraunhofer.aisec.openstack.ConceptListerCommand` which is part of the `codyze-evaluator`.

The concepts provided by the CPG are included in the module `cpg-concepts`.

## Resources on Kotlin?

[The Kotlin Language Documentation](https://kotlinlang.org/docs/home.html) is the official documentation of the Kotlin programming language.
It lists all features of the language with various examples. The section "Concepts" should be the most relevant one.