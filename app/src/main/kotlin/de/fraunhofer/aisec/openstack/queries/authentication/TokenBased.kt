import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.Assumption
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.query.*

/**
 * Determines if the [HttpEndpoint] [this] does not require authentication.
 *
 * Note: This whitelist has to be customized for each project.
 */
fun HttpEndpoint.doesNotNeedAuthentication(): QueryTree<Boolean> {
    // Currently, we assume that only the endpoints under "/v3" (for cinder) and "/v1" (for barbican) need authentication.
    val doesNotNeedAuth = !((this.underlyingNode?.component?.name?.localName == "cinder" &&
            this.path.startsWith("/v3/")) ||
            (this.underlyingNode?.component?.name?.localName == "barbican" &&
                    this.path.startsWith("/v1/")))

    // Creates the QueryTree with the result of the assessment.
    return QueryTree(
        value = doesNotNeedAuth,
        stringRepresentation = if (doesNotNeedAuth)
            "The endpoint $this does not need authentication"
        else
            "The endpoint $this does not need authentication",
        children = mutableListOf(QueryTree(this)),
        node = this
    ).assume(
        AssumptionType.ExhaustiveEnumerationAssumption,
        "We assume that the list of endpoints that do not require authentication is exhaustive and does not contain too many elements.\n\n" +
                "To validate this assumption, it is necessary to check if this list is in accordance with the documentation provided.",
    )
}

/**
 * Checks if the [TranslationResult] [this] contains a [ConfigurationSource] that configures that the provider is a valid token provider.
 */
fun TranslationResult.isTokenProviderConfigured(): QueryTree<Boolean> {
    return this.existsExtended<ConfigurationSource>(
        sel = { config -> config.name.toString() == "keystone.conf" },
        mustSatisfy = { config ->

            val providerGroups = config.groups
                .flatMap { group ->
                    group.options.filter { it.name.localName == "provider" }
                }

            val configuresTokenAuth = providerGroups.singleOrNull { it.evaluate().toString() in tokenProvider } != null

            QueryTree(
                value = configuresTokenAuth,
                stringRepresentation = if (configuresTokenAuth) "The config configures token-based authentication" else "The config does not configure token-based authentication",
                children = mutableListOf(QueryTree(config), QueryTree(providerGroups)),
            )
        },
    )
}

/**
 * The list of valid token providers that are valid for the project.
 *
 * Note: This set may change depending on the project or state-of-the-art.
 */
val tokenProvider = setOf("fernet", "jws")

/**
 * Checks if the [HttpEndpoint] [this] requires token-based authentication. The attribute [HttpEndpoint.authentication] is set by the pass only if a token provider has been configured.
 */
fun HttpEndpoint.hasTokenBasedAuth(): QueryTree<Boolean> {
    val isTokedBasedAuth = this.authentication is TokenBasedAuth
    return QueryTree(
        value = isTokedBasedAuth,
        stringRepresentation = if (isTokedBasedAuth) {
            "The endpoint $this requires token-based authentication"
        } else {
            "The endpoint $this does not require token-based authentication"
        },
        children = mutableListOf(QueryTree(this.authentication)),
        node = this
    )
}

/**
 * Checks if all [HttpEndpoint]s in the [TranslationResult] are either in the list of endpoints that do not require authentication or have a valid (in terms of secure) token-based authentication in-place.
 */
fun doNotRequireOrHaveTokenBasedAuthentication(tr: TranslationResult): QueryTree<Boolean> {
    // Is a valid token provider configured?
    val tokenProviderConfigured = tr.isTokenProviderConfigured()

    return tr.allExtended<HttpEndpoint>(
        mustSatisfy = { endpoint ->
            // The requirement is satisfied if the endpoint has token-based authentication enabled and a valid token provider is configured or if the endpoint does not need authentication.
            (tokenProviderConfigured and endpoint.hasTokenBasedAuth()) or endpoint.doesNotNeedAuthentication()
        }
    )
}