/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.query.QueryOperators
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended

/**
 * This queries checks whether all [HttpEndpoint]s that [shouldHaveAuthentication] have
 * [HttpEndpoint.authentication] enabled.
 */
context(TranslationResult)
fun endpointsAreAuthenticated(
    shouldHaveAuthentication: HttpEndpoint.() -> Boolean
): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<HttpEndpoint>(
        sel = { endpoint ->
            // Only endpoints that are private and therefore should have authentication
            shouldHaveAuthentication(endpoint)
        },
        // See if we find one that does not have authentication
        mustSatisfy = { endpoint ->
            QueryTree(
                value = endpoint.authentication != null,
                children = mutableListOf(QueryTree(endpoint, operator = QueryOperators.EVALUATE)),
                operator = QueryOperators.EVALUATE,
            )
        },
    )
}
