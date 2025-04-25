import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint

/**
 * All HTTPEndpoints in /v3/ for cinder and /v1/ for barbican must have authentication
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.existsExtended<HttpEndpoint>(
        sel = { endpoint ->
            // Filter the respective endpoints
            (endpoint.underlyingNode?.component?.name?.localName == "cinder" &&
                    endpoint.path.startsWith("/v3/")) ||
                    (endpoint.underlyingNode?.component?.name?.localName == "barbican" &&
                            endpoint.path.startsWith("/v1/"))
        },
        // See if they all have authentication
        mustSatisfy = { endpoint -> QueryTree(value = endpoint.authentication != null) },
    )
}
