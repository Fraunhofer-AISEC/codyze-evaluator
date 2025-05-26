package de.fraunhofer.aisec.openstack.queries.keymanagement

import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.logging.*
import de.fraunhofer.aisec.cpg.query.*

/**
 * Secrets must not be logged.
 *
 * This query checks if there is a data flow from any `Secret` Concept to a `LogWrite` Operation possible.
 *
 * **Important note for this query to work as intended:**
 * The nodes implementing the `Secret` concept must have an outgoing DFG edge (typically to the underlyingNode).
 * If this is not desired, an option might be to replace `Secret` with the `GetSecret` operation.
 * Another option could be to use the `startNode = secret.underlyingNode`.
 */
fun noLoggingOfSecrets(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret> { secret ->
        not(
            dataFlow(
                // The source is any data with the Concept `Secret`.
                startNode = secret,
                // May analysis because a single data flow is enough to violate the requirement
                type = May,
                // Consider all paths across functions.
                scope = Interprocedural(),
                // Use Operation `LogWrite` as a sink.
                predicate = { it is LogWrite },
            ) // If this returns a QueryTree<Boolean> with value `true`, a dataflow may be present.
        ) // We want to negate this result because such a flow must not happen.
    }
}