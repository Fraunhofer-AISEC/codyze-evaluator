/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.keymanagement

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.query.*

/**
 * This query enforces the following statement: Secrets must not be logged.
 *
 * This query checks if there is a data flow from any [Secret] concept to a [ogWrite` Operation
 * possible.
 *
 * **Important note for this query to work as intended:** The nodes implementing the `Secret`
 * concept must have an outgoing DFG edge (typically to the underlyingNode). If this is not desired,
 * an option might be to replace `Secret` with the `GetSecret` operation. Another option could be to
 * use the `startNode = secret.underlyingNode`.
 */
context(TranslationResult)
fun noLoggingOfSecrets(): QueryTree<Boolean> {
    val tr = this@TranslationResult
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
