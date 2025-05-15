# Concepts and Operations

## What is it?

We use *Concepts* and *Operations* to represent semantic information about the code within the CPG.
As this information is not part of the original code, we use an [OverlayGraph](https://fraunhofer-aisec.github.io/cpg/CPG/specs/overlays/) to store such information without directly including it in the code-related parts of the CPG.

In general, an *Operation* always represents a certain functionality, i.e., action or behavior, of the code.
A *Concept*, in turn, can be seen as a higher-level abstraction of the code and abstracts some behavior or somehow relevant information and clusters multiple operations or interesting properties related to the same concept.

## How to generate own concepts and operations?

A user can create own concepts and operations by implementing the respective interfaces.
Each concept is represented by a class that extends the `Concept` class.
Each operation is represented by a class that extends the `Operation` class.

Please check if it makes sense for your use-case to implement further methods of these base-classes.
Most likely, this includes overriding `equals`, `hashCode`, and `setDFG`. 

## How are they added to the CPG?

Concepts and Operations can be added to the CPG by [writing custom passes](https://fraunhofer-aisec.github.io/cpg/CPG/impl/passes/) or using our [tagging DSL](tagging-dsl.md).

## How are they linked in the CPG?

The `Concept` and `Operation` are part of the [OverlayGraph](https://fraunhofer-aisec.github.io/cpg/CPG/specs/overlays/).
Each node in the code-related parts of the CPG can be linked to multiple overlay node with the edges `overlayEdges`.
In turn, each overlay node can reach its `underlyingNode`, where currently, only a single node is allowed.
The user can also specify dataflow edges for concepts and operations by overriding default behavior in the `setDFG` method or setting custom edges after generating the respective node.
The Operations are included in the EOG right after their underlying node.
