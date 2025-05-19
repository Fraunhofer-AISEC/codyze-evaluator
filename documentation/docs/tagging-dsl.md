# The "Tagging" DSL

To simplify the process of tagging the source code with `Concept`s and `Operation`s, we provide a DSL (Domain Specific Language).
In general, the user can define custom `Concept`s and `Operation`s within the Kotlin Scripts.
In addition, the DSL allows a more convenient way to add the respective tags to the CPG's representation of the source code.

The tagging DSL is defined in the module `codyze-core` in the file `codyze-core/src/main/kotlin/de/fraunhofer/aisec/codyze/ConceptScriptDefinition.kt`.

To tag the source code, the user can use the following syntax:

```kotlin
tag {
    // Tagging each node of the type NodeType and name "name" with the concept Concept
    each<NodeType>("name").with { Concept() }
    // Tagging each node of the type NodeType and specialProperty set to true with the concept Concept
    each<NodeType>(predicate = { it.specialProperty == true } ).with { Concept() }
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
