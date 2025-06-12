/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.keymanagement

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.query.May
import de.fraunhofer.aisec.cpg.query.QueryOperators
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.dataFlow

/**
 * If a key (e.g. a secret returned by [GetSecret]) is accessed through an [HttpEndpoint], then this
 * endpoint must be authenticated.
 */
context(TranslationResult)
fun keyOnyAccessibleByAuthenticatedEndpoint(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<HttpEndpoint>(
        // A secret reaches this endpoint.
        sel = { endpoint ->
            dataFlow(
                    startNode = endpoint,
                    type = May,
                    direction = Backward(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    predicate = { it is GetSecret },
                )
                .value
        },
        mustSatisfy = { endpoint ->
            // There's some authentication for this endpoint
            QueryTree(
                value = endpoint.authentication != null,
                children =
                    endpoint.authentication?.let {
                        mutableListOf(QueryTree(value = it, operator = QueryOperators.EVALUATE))
                    } ?: mutableListOf(),
                stringRepresentation =
                    "The endpoint $endpoint requires authentication by ${endpoint.authentication}",
                node = endpoint,
                operator = QueryOperators.EVALUATE,
            )
        },
    )
}
