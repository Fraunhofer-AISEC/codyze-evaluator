# The "Tagging" DSL

To simplify the process of tagging the source code with `Concept`s and `Operation`s, we provide a DSL (Domain Specific Language).
In general, the user can define custom `Concept`s and `Operation`s within the Kotlin Scripts.
In addition, the DSL allows a more convenient way to add the respective tags to the CPG's representation of the source code.

The tagging DSL is defined in the module `codyze-core` in the file `codyze-core/src/main/kotlin/de/fraunhofer/aisec/codyze/ConceptScriptDefinition.kt`.

## Where to add Concepts and Tags

The user can define own `Concept`s and `Operation`s in any kotlin file within the analysis project.
We recommend to first check the catalog of existing concepts and operations in the file and, if possible, to extend the catalog with the new concepts and operations instead of creating many project-specific ones.
The project-specific tagging logic can be added in a kotlin script file which can be included in the evaluation project script using the `Tagging` import.
It is also possible to create custom passes if the tagging logic is too complex for the DSL.
This is a kotlin script files which are executed during the translation of the source code.

## Tagging the code

The following example shows a separate file `tagging.codyze.kts` which contains the tagging logic for the project which describes the syntax for tagging the source code:

```kotlin title="tagging.codyze.kts"
project {
    tagging {
        tag {
            // Tagging each node of the type NodeType and name "name" with the concept Concept
            each<NodeType>("name").with { Concept() }
            // Tagging each node of the type NodeType and specialProperty set to true with the concept Concept
            each<NodeType>(predicate = { it.specialProperty == true } ).with { Concept() }
            // Tagging each node of the type NodeType and name "name" with the concept Concept
            each<NodeType>("name").with {
                // Starting from each of the selected nodes of NodeType (they are kept in `node`), you can access specific properties and propagate tags to them.
                // This is useful, e.g., if you want to tag specific arguments of a function call.
                propagate { node.attribute }.with { OtherConcept() }

                Concept()
            }
        }
    }
}
```

To include this file in the evaluation project, the user can add the following line to the evaluation project script:

```kotlin title="project.codyze.kts"
include {
    Tagging from "tagging.codyze.kts"
}
```

The whole tagging logic is encapsulated in a function which is passed to the function `tag`. This forms the outer part
`tag { ... }` of the DSL.

Inside this function, the user can use the function `each` to define which nodes should be tagged. The function `each` accepts the following arguments:

* a type parameter which defines the type `T` of the nodes to be tagged.
* An optional `namePredicate` of type `CharSequence` (e.g., a `String` or `Name`) to match the name of the node.
* An optional `predicate` (i.e., a function accepting a node of type `T` and returning a `Boolean` value) allows to match any of the node's properties or write any other expression that you can come up with.

!!! note "Tagging based on existing overlays"

    If the goal is to tag a node based on an existing OverlayNode (e.g. `Concept` or `Operation`), it is currently necessary to select the underlyingNode and check for the OverlayNodes in the `predicate`.

    Example: `each<Node>( predicate = { it.overlays.any { it is BlockCipherKey } }).with { Secret() }` tags all nodes which have been tagged as `BlockCipherKey` with the `Secret` overlay.

After the call to the function `each`, the actual OverlayNode will be assigned by calling the function `with`.
This function receives a lambda function which returns the OverlayNode to be assigned.
The node itself is available as `this.node` inside the function.

!!! danger

    The `underlyingNode` of the created `OverlayNode` **must not** be passed as a constructor argument here.
    It will be assigned to the object later.

The tagging itself is conducted inside a Pass iterating through the EOG and computing a fixed-point (intraprocedurally).

While the user can access the lattice and state used during the fixed-point iteration, we strongly discourage using it unless the user really knows what he/she is doing.

!!! note

    The ordering of the tagging is important.
    If you want to build upon existing tags of a node, you should make sure that this also happens in the correct order within the file.
