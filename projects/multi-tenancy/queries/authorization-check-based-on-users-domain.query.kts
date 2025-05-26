import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize

/**
 * Extracts relevant target values (e.g., user ID and project ID) from the request context of
 * the [HttpEndpoint] [this].
 *
 * Note: This logic may need to be adapted if other identifiers are also relevant.
 */
fun HttpEndpoint.targetValuesForUserOrProject(): Set<Node> {
    val userInfo = (this.requestContext as? ExtendedRequestContext)?.userInfo
    userInfo?.let {
        return setOf(userInfo.projectId, userInfo.userId)
    }
    return setOf()
}

/**
 * Checks if there is a data flow from any authorization target to one of the provided
 * [targetValues].
 */
fun HttpEndpoint.hasDataFlowToDomain(targetValues: Set<Node>): QueryTree<Boolean> {
    return this.authorization
        ?.ops
        ?.filterIsInstance<Authorize>()
        ?.flatMap { auth ->
            auth.targets.map { target ->
                dataFlow(
                    startNode = target,
                    type = Must,
                    direction = Backward(GraphToFollow.DFG),
                    predicate = { dataFlowNode ->
                        val ref = dataFlowNode as? Reference
                        ref?.refersTo?.let { refersTo ->
                            targetValues.contains(refersTo)
                        } ?: false
                    },
                )
            }
        }
        ?.mergeWithAll()
        ?: QueryTree(false, stringRepresentation = "No data flow to domain due to missing authorization")
}

/**
 * Checks if there is a data flow from the policy reference into the `action` argument of the
 * `policy.authorize` call.
 *
 * The `action` argument is expected to be the second argument of the `authorize` call.
 */
fun HttpEndpoint.hasDataFlowFromPolicyToAuthorizeAction(): QueryTree<Boolean> {
    val policyRef =
        (this.authorization as? AuthorizationWithPolicy)?.policy?.policyRef
            ?: return QueryTree(
                value = false,
                stringRepresentation = "No policy found",
                node = this,
            )

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
 * Checks that when authorizing a request, the caller's domain/project is used in the authorization check
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
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