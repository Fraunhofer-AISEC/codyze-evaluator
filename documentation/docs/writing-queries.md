# How do I write a query?

A query is a piece of code which retrieves information from the CPG (or a part of it) to assess if a statement holds or not.

The main sources for the implementation can be found in the files `Query.kt`, `FlowQueries.kt` and `QueryTree.kt` in the module `cpg-analysis`.

## Where to add Queries

Queries can be added everywhere in the [evaluation project](analyzing-project.md#project-structure).
However, we recommend to add them to the `queries` folder to simplify finding them.
They must be included in a kotlin file (file ending `.kt`) which is included in the sources of the project.
Finally, you have to call the queries in the `requirements` block, or in a query called therein, of the [evaluation project script](analyzing-project.md#defining-an-analysis-project), or they won't be assessed.

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
A detailed explanation of the parameters `direction`, `type`, `sensitivities` and `scope` which configure these functions is provided in [program-analysis-basics.md](program-analysis-basics.md).

### `dataFlow`

<div class="grid" markdown>

=== "Signature"

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

=== "Goal of the function"

    Follows the `Dataflow` edges from `startNode` in the given `direction` until reaching a node fulfilling `predicate`.

    The interpretation of the analysis result can be configured as must or may analysis by setting the `type` parameter.

    Note that this function only reasons about existing DFG paths, and it might not be sufficient if you actually want a guarantee that some action always happens with the data.
    In this case, you may need to check the `executionPath` or `alwaysFlowsTo`.

=== "Parameters"

    * `startNode`: The node from which the data flow should be followed.
    * `direction`: See the [explanation of class `AnalysisDirection`](program-analysis-basics.md/#analysisdirection)
    * `type`: See the [explanation of class `AnalysisType`](program-analysis-basics.md/#analysistype)
    * `sensitivities`: See the [explanation of Sensitivities](program-analysis-basics.md/#sensitivities)
    * `scope`: See the [explanation of class `AnalysisScope`](program-analysis-basics.md/#analysisscope)
    * `earlyTermination`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
      analysis/traversal of this path will stop and return `false`. If `null` is provided, the analysis will not stop.
    * `predicate`: This function marks the desired end of a dataflow path. If this function returns `true`, the analysis/traversal of this path will stop.

</div>

### `executionPath`

<div class="grid" markdown>

=== "Signature"

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

=== "Goal of the function"

    Follows the Evaluation Order Graph (EOG) edges from startNode in the given direction until reaching a node fulfilling predicate.

    The interpretation of the analysis result can be configured as must or may analysis by setting the type parameter.

    This function reasons about execution paths in the program and can be used to determine whether a specific action or condition is reachable during execution.

=== "Parameters"

    * `startNode`: The node from which the execution path should be followed.
    * `direction`: See the [explanation of class `AnalysisDirection`](program-analysis-basics.md/#analysisdirection)
    * `type`: See the [explanation of class `AnalysisType`](program-analysis-basics.md/#analysistype)
    * `sensitivities`: See the [explanation of Sensitivities](program-analysis-basics.md/#sensitivities)
    * `scope`: See the [explanation of class `AnalysisScope`](program-analysis-basics.md/#analysisscope)
    * `earlyTermination`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
      analysis/traversal of this path will stop and return `false`. If `null` is provided, the analysis will not stop.
    * `predicate`: This function marks the desired end of an execution path. If this function returns `true`, the analysis/traversal of this path will stop.

</div>

### `alwaysFlowsTo`

<div class="grid" markdown>

=== "Signature"

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

=== "Goal of the function"

    Checks that the data originating from `this` reach a sink (fulfilling `predicate`) on each execution path.

=== "Parameters"

    * `allowOverwritingValue`: If set to `true`, the value of a variable can be changed before reaching `predicate` but the function would still return `true`.
      If set to `false`, overwriting the value held in `this` before reaching a sink specified by `predicate` will lead to a `false` result.
    * `identifyCopies`: If set to `true`, the query will aim to figure out if the dataflow of one object is copied to another object which requires separate tracking of the instances (e.g. if they require separate deletion, or other clearing/validating actions).
    * `stopIfImpossible`: If set to `true`, the analysis will stop if it is impossible to reach a node fulfilling `predicate`.
      This is useful for performance reasons, as it avoids unnecessary iterations.
      In particular, it checks if any dataflow exists to any node which is in scope of a function containing the call-site of a function declaration, we stop iterating.
    * `earlyTermination`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
      analysis/traversal of this path will stop and return `false`. If `null` is provided, the analysis will not stop.
    * `scope`: See the [explanation of class `AnalysisScope`](program-analysis-basics.md/#analysisscope)
    * `sensitivities`: See the [explanation of Sensitivities](program-analysis-basics.md/#sensitivities)
    * `predicate`: This function marks the desired end of a combined dataflow and execution path.
      If this function returns `true`, the analysis/traversal of this path will stop.

</div>

### `dataFlowWithValidator`

<div class="grid" markdown>

=== "Signature"

    ```kotlin
    fun dataFlowWithValidator(
        source: Node,
        validatorPredicate: (Node) -> Boolean,
        sinkPredicate: (Node) -> Boolean,
        scope: AnalysisScope,
        vararg sensitivities: AnalysisSensitivity,
    ): QueryTree<Boolean>
    ```

=== "Goal of the function"

    Checks that the data originating from `source` are validated by a validator (fulfilling `validatorPredicate`) on each execution path before reaching a sink marked by `sinkPredicate`.

    This function always runs a forward analysis and combines the DFG and EOG.

=== "Parameters"

    * `source`: The node from which the dataflow path should be followed.
    * `validatorPredicate`: If applying this function to a `Node` returns `true` before a node fulfilling `predicate`, the
      analysis/traversal of this path will stop and return `true`.
    * `sinkPredicate`: This function marks a sink, where it is not permitted to reach the sink without always passing through a validator characterized by `validatorPredicate`.
      If this function returns `true`, the analysis/traversal of this path will stop and return `false`.
    * `scope`: See the [explanation of class `AnalysisScope`](program-analysis-basics.md/#analysisscope)
    * `sensitivities`: See the [explanation of Sensitivities](program-analysis-basics.md/#sensitivities)

</div>

## The class `QueryTree`

The class `de.fraunhofer.aisec.cpg.query.QueryTree` serves as a wrapper around the result of a query and the sub-statements which were used to retrieve the result.
It is parametrized with a type `T` which is the type of the field `value`.

Fields:

* `value`: The result of the query, which is of type `T`. Frequent values are boolean values which determine if the query was successful or not, lists of nodes which were found by the query (i.e., representing paths), or other values representing a possible value of a variable.
* `children`: A list of sub-queries which were evaluated to retrieve the result in `value`.
* `stringRepresentation`: A human-readable string representation of the query's result.
  It typically includes the operation/function which was performed, its inputs and the computed result which is now held in `value`.
* `assumptions`: A list of assumptions which were collected on evaluation.

Numerous methods allow to evaluate the queries while keeping track of all the steps.
Currently, the following operations are supported:

* **eq**: Equality of two values.
* **ne**: Inequality of two values.
* **IN**: Checks if a value is contained in a [Collection]
* **IS**: Checks if a value implements a type ([Class]).

Additionally, some functions are available only for certain types of values.

For boolean values:

* **and**: Logical and operation (&&)
* **or**: Logical or operation (||)
* **xor**: Logical exclusive or operation (xor)
* **implies**: Logical implication

For numeric values:

* **gt**: Grater than (>)
* **ge**: Grater than or equal (>=)
* **lt**: Less than (<)
* **le**: Less than or equal (<=)

The top-level result of any query must be a `QueryTree<Boolean>`.
However, it is sometimes necessary to aggregate the results of multiple sub-queries with methods of the kotlin standard library (such as `map` for collections), which does not return a `QueryTree<Boolean>` itself.
In this case, you can simply create a `QueryTree<Boolean>` by calling the constructor.
It may be handy to implement some helper functions for frequent purposes as part of the Codyze Evaluator and import these extensions in the query scripts.
