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

We provide a list of current concepts and operations under [./concepts-and-operations.md].
To generate/update this list, you can run the program `de.fraunhofer.aisec.openstack.ConceptListerCommand` which is part of the `openstack-checker`.

# How do I write a query?

## Starting point: Choosing between `allExtended` and `existsExtended`

You would typically start writing a query by using one of the two functions `allExtended` or `existsExtended`.
If a certain property should be fulfilled at least once in the whole codebase, you can use `existsExtended`, while `allExtended` serves to check if the property is fulfilled for all nodes (which you select).
Both functions receive the following arguments:
* The type of node to consider is provided by the type-parameter `T`. E.g. `existsExtended<Secret>` will only consider nodes of type `Secret`.
* The optional parameter `sel` can be used to further filter these start nodes.
  If no value is provided, all nodes of type `T` will be considered.
  `sel` expects a function receiving a node of type `T` and returning a boolean value.
  You can provide this in curly braces, e.g. `{secret -> secret.name.localName == "mySecret"}` will consider only secrets with local name `mySecret`.
* The mandatory requirement `mustSatisfy` is a function which receives a node of type `T` and returns an object of type `QueryTree<Boolean>`.
  This function is the property which has to be fulfilled for one or all nodes which have been selected so far.
  Again, you can provide this in curly braces.

Few notes on Kotlin:
* The default name of a lambda's parameter is `it`, but you can also provide a name for the parameter followed by an arrow, like `secret` in the example above.
* If you use the default parameter name `it`, you can omit the parameter name and arrow in the lambda, e.g. `{ it.name.localName == "mySecret" }`.
* Kotlin has named arguments, which means that you can provide the name of the parameter followed by `=` and the value.
  E.g., `n.allExtended<Secret>(mustSatisfy = { min(it.keySize) ge const(256) })` is equivalent to `n.allExtended<Secret>({ min(it.keySize) ge const(256) })`.
* Kotlin allows you to move the last argument out of the brackets if it's a lambda function. E.g., `n.allExtended<Secret> { min(it.keySize) ge const(256) }` is equivalent to `n.allExtended<Secret>({ min(it.keySize) ge const(256) })` which is again equivalent to `allExtended<Secret>(mustSatisfy = { min(it.keySize) ge const(256) })`.

## Flow-based functions of the Query API

Currently, following four functions of the Query API can be used to reason about the flow of data or control in the program:
`dataFlow`, `dataFlowWithValidator`, `executionPath` and `alwaysFlowsTo`.
A detailed explanation of the parameters `direction`, `type`, `sensitivities` and `scope` which configure these functions is provided in [./program-analysis-basics.md].
The remaining parameters are explained in this section.

### `dataFlow`

<table>
<tr>
<td> Signature </td>
<td>

```kotlin
fun dataFlow(
    startNode: Node,
    direction: AnalysisDirection = Forward(GraphToFollow.DFG),
    type: AnalysisType = May,
    vararg sensitivities: AnalysisSensitivity = FieldSensitive + ContextSensitive,
    scope: AnalysisScope = Interprocedural(),
    earlyTermination: ((Node) -> Boolean)? = null,
    predicate: (Node) -> Boolean,
): QueryTree<Boolean>

```

</td>
</tr>
<tr>
<td>Goal of the function</td>
<td>

Follows the `Dataflow` edges from `startNode` in the given `direction` until reaching a node fulfilling `predicate`.

The interpretation of the analysis result can be configured as must or may analysis by setting the `type` parameter.

Note that this function only reasons about existing DFG paths, and it might not be sufficient if you actually want a guarantee that some action always happens with the data.
In this case, you may need to check the `executionPath` or `alwaysFlowsTo`.

</td>
</tr>
<tr>
<td>Parameters:</td>
<td>

* `startNode`: The node from which the data flow should be followed.
* `earlyTermination`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
  analysis/traversal of this path will stop and return `false`. If `null` is provided, the analysis will not stop.
* `predicate`: This function marks the desired end of a dataflow path. If this function returns `true`, the analysis/traversal of this path will stop.

</td>
</tr>
</table>

### `executionPath`

<table>
<tr>
<td> Signature </td>
<td>

```kotlin
fun executionPath(
    startNode: Node,
    direction: AnalysisDirection = Forward(GraphToFollow.EOG),
    type: AnalysisType = May,
    scope: AnalysisScope = Interprocedural(),
    earlyTermination: ((Node) -> Boolean)? = null,
    predicate: (Node) -> Boolean,
): QueryTree<Boolean>
```

</td>
<tr><td>Goal of the function</td>
<td>Follows the Execution Order Graph (EOG) edges from startNode in the given direction until reaching a node fulfilling predicate.

The interpretation of the analysis result can be configured as must or may analysis by setting the type parameter.

This function reasons about execution paths in the program and can be used to determine whether a specific action or condition is reachable during execution.
</td>
</tr>
<tr><td>Parameters:</td>
<td>

* `startNode`: The node from which the execution path should be followed.
* `earlyTermination`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
  analysis/traversal of this path will stop and return `false`. If `null` is provided, the analysis will not stop.
* `predicate`: This function marks the desired end of an execution path. If this function returns `true`, the analysis/traversal of this path will stop.

</td>
</tr>
</table>


### `dataFlowWithValidator`

<table>
<tr>
<td> Signature </td>
<td>

```kotlin
fun dataFlowWithValidator(
    source: Node,
    validatorPredicate: (Node) -> Boolean,
    sinkPredicate: (Node) -> Boolean,
    scope: AnalysisScope,
    vararg sensitivities: AnalysisSensitivity,
): QueryTree<Boolean>
```

</td>
</tr>
<tr>
<td>Goal of the function</td>
<td>

Checks that the data originating from `source` are validated by a validator (fulfilling `validatorPredicate`) on each execution path before reaching a sink marked by `sinkPredicate`.

</td>
</tr>
<tr>
<td>Parameters:</td>
<td>

* `source`: The node from which the dataflow path should be followed.
* `validatorPredicate`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
  analysis/traversal of this path will stop and return `true`.
* `sinkPredicate`: This function marks a sink, where it is not permitted to reach the sink without always passing through a validator characterized by `validatorPredicate`.
  If this function returns `true`, the analysis/traversal of this path will stop and return `false`.

</td>
</tr>
</table>

### `alwaysFlowsTo`

<table>
<tr>
<td> Signature </td>
<td>

```kotlin
fun Node.alwaysFlowsTo(
    allowOverwritingValue: Boolean = false,
    earlyTermination: ((Node) -> Boolean)? = null,
    identifyCopies: Boolean = true,
    stopIfImpossible: Boolean = true,
    scope: AnalysisScope,
    vararg sensitivities: AnalysisSensitivity =
        ContextSensitive + FieldSensitive + FilterUnreachableEOG,
    predicate: (Node) -> Boolean,
): QueryTree<Boolean>
```

</td>
</tr>
<tr>
<td>Goal of the function</td>
<td>

</td>
</tr>
<tr>
<td>Parameters:</td>
<td>

*

</td>
</tr>
</table>

## Creating a `QueryTree` object


# Multiple concepts or operations for a single node?