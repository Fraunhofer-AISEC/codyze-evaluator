import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint


fun HttpEndpoint.shouldHaveAuthentication(): Boolean {
    return (this.underlyingNode?.component?.name?.localName == "cinder" &&
            this.path.startsWith("/v3/")) ||
            (this.underlyingNode?.component?.name?.localName == "barbican" &&
                    this.path.startsWith("/v1/"))
}

fun isTokenProvider(tr: TranslationResult, provider: Set<String>): Boolean {
    return tr.exists<ConfigurationSource>(
        sel = { config -> config.name.toString() == "keystone.conf" },
        mustSatisfy = { config ->
            config.groups
                .flatMap { group ->
                    group.options.filter { it.name.localName == "provider" }
                }
                .singleOrNull { it.evaluate().toString() in provider } != null
        },
    )
        .first
}

fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    val tokenProvider = setOf("fernet", "jws")
    result.allExtended<HttpEndpoint>(
        sel = { endpoint -> endpoint.shouldHaveAuthentication() && isTokenProvider(result, provider = tokenProvider) },
        mustSatisfy = { endpoint ->
            QueryTree(
                value = endpoint.authentication is TokenBasedAuth,
                children = mutableListOf(QueryTree(endpoint)),
            )
        },
}