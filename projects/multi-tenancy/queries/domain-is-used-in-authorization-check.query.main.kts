import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint


fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<HttpEndpoint>(
        sel = { it.authorization != null },
        mustSatisfy = { endpoint ->
            val tmp = endpoint.authorization?.ops?.filterIsInstance<Authorize>()?.map
            {
                dataFlow(
                    startNode = it.target,
                    type = Must,
                    direction = Backward(GraphToFollow.DFG),
                    predicate = { endpoint.context?.userInfo?.projectId == it },
                )
            } ?: listOf()
            QueryTree<Boolean>(
                value = tmp.all { it.value },
                children = tmp.toMutableList(),
                node = endpoint
            )
        }
    )
}