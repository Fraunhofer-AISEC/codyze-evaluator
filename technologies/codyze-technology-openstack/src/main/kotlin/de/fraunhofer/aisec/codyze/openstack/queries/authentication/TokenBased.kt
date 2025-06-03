/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack.queries.authentication

import de.fraunhofer.aisec.codyze.concepts.auth.ExtendedRequestContext
import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.*
import de.fraunhofer.aisec.cpg.query.*

/**
 * Checks if there is a data flow from the [ExtendedRequestContext.token] into the [TokenBasedAuth].
 */
context(TranslationResult)
fun hasDataFlowToToken(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<ExtendedRequestContext>(
        mustSatisfy = { ctx ->
            val token = ctx.token
            if (
                token == null ||
                    ctx.userInfo?.userId == null ||
                    ctx.userInfo?.domainId == null ||
                    ctx.userInfo?.projectId == null
            ) {
                // If information is missing, we cannot determine the data flows and want to fail
                QueryTree(false, node = ctx, stringRepresentation = "Invalid Request context")
            } else {
                dataFlow(
                    // We start from the token in the request context
                    startNode = token,
                    // We want to find out which data can flow there, so we follow the data flow
                    // backwards
                    direction = Backward(GraphToFollow.DFG),
                    // All paths must lead to a TokenBasedAuth because otherwise, we detected a path
                    // which uses another token which was not used in the authentication.
                    type = Must,
                    predicate = { token ->
                        token.overlays.filterIsInstance<TokenBasedAuth>().isNotEmpty()
                    },
                )
            }
        }
    )
}
