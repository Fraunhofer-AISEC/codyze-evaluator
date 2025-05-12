# Where to find...

## the code of the Query API?

The Query API is documented under the following page: [https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/](https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/)

The Query API is mostly defined in three files in the module `cpg-analysis`:
* Query.kt
* FlowQueries.kt
* QueryTree.kt

Note: A `QueryTree` serves as a wrapper around the results and the sub-statements which were used to retrieve the result.
It also contains the assumptions which were collected on evaluation and a human-readable string representation.

## concepts and operations?

We provide a list of current concepts and operations under [./concepts-and-operations.md].
To update this list, you can run ... ( TODO @KuechA look up the tool again )
