package de.fraunhofer.aisec.openstack.queries.authorization

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.query.Must
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.dataFlow
import de.fraunhofer.aisec.cpg.query.mergeWithAll
import de.fraunhofer.aisec.openstack.concepts.auth.AuthorizationWithPolicy
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext


/**
 * Retrieves all [Authorize] operations related to the [HttpEndpoint] [this] and checks if there is
 * a data flow from each of these authorizations' authorization targets to one of the provided
 * [targetValues]. If there is no [HttpEndpoint.authorization] present, it returns a [QueryTree] with value `false`.
 */
fun HttpEndpoint.hasDataFlowToDomain(targetValues: Set<Node>): QueryTree<Boolean> {
    return this.authorization
        ?.ops
        ?.filterIsInstance<Authorize>() // Get all Authorize operations related to this endpoint
        ?.flatMap { auth ->
            // For each Authorize operation, check if there is a data flow from its targets to the provided targetValues
            auth.targets.map { target ->
                dataFlow(
                    // Start at the target of the authorization
                    startNode = target,
                    // We want to ensure that there is a data flow to the target values on each path
                    type = Must,
                    // The target values are expected to be in the backward data flow graph, i.e., have been specified before the authorization
                    direction = Backward(GraphToFollow.DFG),
                    // The predicate checks if the data flow node is one of the target values
                    predicate = { dataFlowNode -> dataFlowNode in targetValues },
                )
            }
        }
        ?.mergeWithAll() // Merge all data flows from the Authorize operations and only accept the result if all of them are satisfied
        ?: QueryTree(
            false, // If there is no authorization, we cannot have a data flow to the domain and return false.
            stringRepresentation = "No data flow to domain due to missing authorization",
        )
}

/**
 * Extracts relevant target values (e.g., user ID and project ID) from the request context of
 * the [HttpEndpoint] [this].
 *
 * Note: This logic may need to be adapted if other identifiers are also relevant.
 */
fun HttpEndpoint.targetValuesForUserOrProject(): Set<Node> {
    val userInfo = (this.requestContext as? ExtendedRequestContext)?.userInfo
    return setOfNotNull(userInfo?.projectId, userInfo?.userId)
}

/**
 * Checks if there is a data flow from the policy reference into the `action` argument of the
 * `policy.authorize` call.
 *
 * The `action` argument is expected to be the second argument of the `authorize` call.
 *
 * Note: This function is specific to the OpenStack authorization model and the call to `policy.authorize`.
 */
fun HttpEndpoint.hasDataFlowFromPolicyToAuthorizeAction(): QueryTree<Boolean> {
    // Retrieve the policy reference from the authorization.
    // If there is no policy, return a QueryTree with value false, indicating that no policy was found.
    val policyRef =
        (this.authorization as? AuthorizationWithPolicy)?.policy?.policyRef
            ?: return QueryTree(
                value = false,
                stringRepresentation = "No policy found",
                node = this,
            )

    // Starting from the policy reference, we want to find a data flow to the `action` argument possible
    return dataFlow(
        startNode = policyRef,
        predicate = { dataflowNode ->
            val authorizeCall = dataflowNode.astParent as? CallExpression
            authorizeCall?.overlays?.filterIsInstance<Authorize>()?.isNotEmpty() == true &&
                    // Check if the data flow matches the `action` argument, which is expected to be
                    // the second argument of the authorize call
                    authorizeCall.arguments.getOrNull(1) == dataflowNode
        },
    )
}

/**
 * When authorizing a request, the caller’s domain/project is used in the authorization check.
 * This function checks if all [HttpEndpoint]s with an authorization fulfill the following requirements:
 *
 * 1. The "target" of the authorization is always given by the authorization targets (e.g., user ID, project ID) of the [ExtendedRequestContext] handled by this [HttpEndpoint].
 * 2. There is a policy reference specified and it flows into the `action` argument of the `policy.authorize` call.
 */
fun endpointsAreAuthenticated(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<HttpEndpoint>(
        sel = { it.authorization != null },
        mustSatisfy = { endpoint ->
            val targetValues = endpoint.targetValuesForUserOrProject()
            if (targetValues.isEmpty()) {
                QueryTree(false, stringRepresentation = "No target values found")
            } else {
                endpoint
                    .hasDataFlowToDomain(targetValues)
                    .and(endpoint.hasDataFlowFromPolicyToAuthorizeAction())
            }
        },
    )
}