/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.query.*

/**
 * Data flows from user requests are not stored in global variables (since they are assumed to be
 * request-independent) or they are deleted after the request is answered.
 *
 * The [requestSelector] parameter allows to select specific nodes of type [T] to consider to be
 * "user requests" to check for data flows.
 */
context(TranslationResult)
inline fun <reified T : Node> noDataFlowsToGlobals(
    noinline requestSelector: (T) -> Boolean = { true }
): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<T>(requestSelector) { request ->
        // Dataflows from the request do not flow into a global variable
        not(
            dataFlow(
                // The request is the starting point of the dataflow
                startNode = request,
                // We follow the DFG
                direction = Forward(GraphToFollow.DFG),
                // A single violation is problematic
                type = May,
                // Consider all paths
                scope = Interprocedural(),
                // Violation if the target is a global variable which is not deleted on each path.
                predicate = { it is Reference && it.isGlobal() && !it.isAlwaysCleared() },
            )
        )
    }
}

/** Checks if the reference refers to a global variable. */
fun Reference.isGlobal(): Boolean = (this.refersTo as? VariableDeclaration)?.isGlobal == true

/**
 * Determines that the reference is always cleared with a
 * [de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate] operation.
 */
fun Reference.isAlwaysCleared(): Boolean {
    return this.alwaysFlowsTo(
            // We perform an interprocedural analysis.
            scope = Interprocedural(),
            // We do not want to track unreachable EOG paths, and we perform a
            // context- and field-sensitive analysis.
            sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
            // We require a de-allocate operation to be present which affects the reference.
            predicate = { it is DeAllocate },
        )
        .value
}
