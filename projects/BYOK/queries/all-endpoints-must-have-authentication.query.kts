import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [HttpEndpoint] it is invoked on either has cinder as underlyingNode
 * with the path "/v3" or barbican with the path "/v1".
 *
 * @return `true` if this [HttpEndpoint] should have authentication.
 */
fun HttpEndpoint.shouldHaveAuthentication(): Boolean {
    return (this.underlyingNode?.component?.name?.localName == "cinder" &&
            this.path.startsWith("/v3/")) ||
            (this.underlyingNode?.component?.name?.localName == "barbican" &&
                    this.path.startsWith("/v1/"))
}

/**
 * All HTTPEndpoints that are private should have authentication methods
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.existsExtended<HttpEndpoint>(
        sel = { endpoint ->
            // Only endpoints that are private and therefore should have authentication
            endpoint.shouldHaveAuthentication()
        },
        // See if we find one that does not have authentication
        mustSatisfy = { endpoint ->
            QueryTree(
                value = endpoint.authentication == null,
                children = mutableListOf(QueryTree(endpoint)),
            )
        },
    )
}
