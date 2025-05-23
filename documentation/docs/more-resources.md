# Where to find...

## the code of the Query API?

The Query API is documented under the following page: [https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/](https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/)

The Query API is mostly defined in three files in the module `cpg-analysis`:
* Query.kt
* FlowQueries.kt
* QueryTree.kt

Note: A `QueryTree` serves as a wrapper around the results and the sub-statements which were used to retrieve the result.
It also contains the assumptions which were collected on evaluation and a human-readable string representation.

## `Concept`s and `Operation`s?

We provide a list of current concepts and operations under [./list-concepts-and-operations.md].
To generate/update this list, you can run the program `de.fraunhofer.aisec.openstack.ConceptListerCommand` which is part of the `openstack-checker`.

The concepts provided by the CPG are included in the module `cpg-concepts`.

## Resources on Kotlin?

[The Kotlin Language Documentation](https://kotlinlang.org/docs/home.html) is the official documentation of the Kotlin programming language.
It lists all features of the language with various examples. The section "Concepts" should be the most relevant one.