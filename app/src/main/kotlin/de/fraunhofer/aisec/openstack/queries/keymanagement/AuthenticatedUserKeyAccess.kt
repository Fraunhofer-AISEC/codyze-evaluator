/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.keymanagement

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Interprocedural
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.query.May
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.dataFlow

/**
 * Access to Barbican keys must be restricted to authenticated users, i.e., each Barbican REST API
 * that provides access to K must be connected to an Authentication concept.
 */
fun keyAccessWithAuthenticationToken(tr: TranslationResult): QueryTree<Boolean> {
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
                    endpoint.authentication?.let { mutableListOf(QueryTree(value = it)) }
                        ?: mutableListOf(),
                stringRepresentation =
                    "The endpoint $endpoint requires authentication by ${endpoint.authentication}",
                node = endpoint,
            )
        },
    )
}
