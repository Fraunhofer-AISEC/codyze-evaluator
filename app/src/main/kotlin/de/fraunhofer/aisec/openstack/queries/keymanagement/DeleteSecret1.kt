package de.fraunhofer.aisec.openstack.queries.keymanagement

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.ContextSensitive
import de.fraunhofer.aisec.cpg.graph.FieldSensitive
import de.fraunhofer.aisec.cpg.graph.FilterUnreachableEOG
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.alwaysFlowsTo

/**
 * Delete secret data.
 *
 * This query has the following interpretation of this statement:
 * If data is retrieved from a `GetSecret` operation, it must be
 * deleted on each outgoing EOG-path.
 */
fun deleteSecretOnEOGPaths(tr: TranslationResult): QueryTree<Boolean> {
    // The requirement must hold for all data introduced by a `GetSecret` operation.
    return tr.allExtended<GetSecret>(
        // There are no further filters for the starting point of the query.
        sel = null,
        mustSatisfy = { secret ->
            // For each secret, we check if it is de-allocated.
            // The function `alwaysFlowsTo` checks if there's a data flow to a node fulfilling
            // the predicate on every possible execution path starting at the node `secret`.
            // Note: The function `alwaysFlowsTo` also tracks different paths in the DFG if
            // it splits up by copying data (e.g. to a new object, slicing, ...). The currently
            // supported operations are defined by `Node.generatesNewData()`.
            secret.alwaysFlowsTo(
                // We perform an interprocedural analysis.
                scope = Interprocedural(),
                // We do not want to track unreachable EOG paths and we perform a
                // context- and field-sensitive analysis.
                // It would be possible to add `Implicit` to consider implicit dataflows.
                sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
                // We require a de-allocate operation to be present which affects the secret.
                predicate = { it is DeAllocate },
            )
        },
    )
}
