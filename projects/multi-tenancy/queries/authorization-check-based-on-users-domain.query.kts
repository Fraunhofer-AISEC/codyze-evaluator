import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.openstack.concepts.auth.Authorize

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<HttpEndpoint>(
        sel = { it.authorization != null },
        mustSatisfy = { endpoint ->
            val tmp =
                endpoint.authorization?.ops?.filterIsInstance<Authorize>()?.flatMap { auth
                    ->
                    auth.targets.map { target ->
                        dataFlow(
                            startNode = target,
                            type = Must,
                            direction = Backward(GraphToFollow.DFG),
                            predicate = { dataFlowNode ->
                                val data = dataFlowNode as? Reference
                                val userInfo =
                                    (endpoint.requestContext as? ExtendedRequestContext)
                                        ?.userInfo
                                data?.refersTo == userInfo?.projectId ||
                                        data?.refersTo == userInfo?.userId
                            },
                        )
                    }
                } ?: listOf()
            QueryTree<Boolean>(
                value = tmp.all { it.value },
                children = tmp.toMutableList(),
                node = endpoint,
            )
        },
    )
}