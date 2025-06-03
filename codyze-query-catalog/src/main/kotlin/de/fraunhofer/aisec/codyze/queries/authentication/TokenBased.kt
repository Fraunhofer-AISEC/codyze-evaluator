/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.*
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext

/**
 * The list of valid token providers that are valid for the project.
 *
 * Note: This set may change depending on the project or state-of-the-art.
 */
val tokenProvider = setOf("fernet", "jws")

/**
 * Currently, we assume that only the endpoints under "/v3" (for cinder) and "/v1" (for barbican)
 * need authentication.
 */
val requireAuthentication = setOf(Pair("cinder", "/v3/"), Pair("barbican", "/v1/"))

/**
 * Determines if the [de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint] [this] does not
 * require authentication.
 *
 * Note: This whitelist has to be customized for each project.
 */
fun HttpEndpoint.doesNotNeedAuthentication(): QueryTree<Boolean> {
    // Checks if the endpoint is in the list of endpoints that do not require authentication.
    val doesNotNeedAuth =
        requireAuthentication.none {
            it.first == this.underlyingNode?.component?.name?.localName &&
                this.path.startsWith(it.second)
        }

    // Creates the QueryTree with the result of the assessment.
    return QueryTree(
            value = doesNotNeedAuth,
            stringRepresentation =
                if (doesNotNeedAuth) "The endpoint $this does not need authentication"
                else "The endpoint $this does not need authentication",
            children = mutableListOf(QueryTree(this)),
            node = this,
        )
        .assume(
            AssumptionType.ExhaustiveEnumerationAssumption,
            "We assume that the list of endpoints that do not require authentication is exhaustive and does not contain too many elements.\n\n" +
                "To validate this assumption, it is necessary to check if this list is in accordance with the documentation provided.",
        )
}

/**
 * Checks if the [de.fraunhofer.aisec.cpg.TranslationResult] [this] contains a
 * [de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource] that configures that the
 * provider is a valid token provider.
 */
fun TranslationResult.isTokenProviderConfigured(): QueryTree<Boolean> {
    return this.existsExtended<ConfigurationSource>(
        sel = { config -> config.name.toString() == "keystone.conf" },
        mustSatisfy = { config ->
            val providerGroups =
                config.groups.flatMap { group ->
                    group.options.filter { it.name.localName == "provider" }
                }

            val configuresTokenAuth =
                providerGroups.singleOrNull { it.evaluate().toString() in tokenProvider } != null

            QueryTree(
                value = configuresTokenAuth,
                stringRepresentation =
                    if (configuresTokenAuth) "The config configures token-based authentication"
                    else "The config does not configure token-based authentication",
                children = mutableListOf(QueryTree(config), QueryTree(providerGroups)),
            )
        },
    )
}

/**
 * Checks if the [de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint] [this] requires
 * token-based authentication. The attribute
 * [de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint.authentication] is set by the pass only
 * if a token provider has been configured.
 */
fun HttpEndpoint.hasTokenBasedAuth(): QueryTree<Boolean> {
    val isTokedBasedAuth = this.authentication is TokenBasedAuth
    return QueryTree(
        value = isTokedBasedAuth,
        stringRepresentation =
            if (isTokedBasedAuth) {
                "The endpoint $this requires token-based authentication"
            } else {
                "The endpoint $this does not require token-based authentication"
            },
        children = mutableListOf(QueryTree(this.authentication)),
        node = this,
    )
}

/**
 * Todo: Add documentation on which security statement is enforced
 *
 * Checks if all [de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint]s in the
 * [de.fraunhofer.aisec.cpg.TranslationResult] are either in the list of endpoints that do not
 * require authentication or have a valid (in terms of secure) token-based authentication in-place.
 */
context(TranslationResult)
fun tokenBasedAuthenticationWhenRequired(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    // Is a valid token provider configured?
    val tokenProviderConfigured = tr.isTokenProviderConfigured()

    return tr.allExtended<HttpEndpoint>(
        mustSatisfy = { endpoint ->
            // The requirement is satisfied if the endpoint has token-based authentication enabled
            // and a valid token provider is configured or if the endpoint does not need
            // authentication.
            (tokenProviderConfigured and endpoint.hasTokenBasedAuth()) or
                endpoint.doesNotNeedAuthentication()
        }
    )
}

/**
 * Checks if all access tokens used for authentication are validated by the token-based
 * authentication and if they come from the request context.
 */
fun accessTokenIsTiedToRequestContextQuery(tr: TranslationResult): QueryTree<Boolean> {
    return tr.usesSameTokenAsCredential() and tr.hasDataFlowToToken()
}

/**
 * Checks if any [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate] uses a
 * [de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth] where the token is equal to the
 * credential of that [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate].
 */
fun TranslationResult.usesSameTokenAsCredential(): QueryTree<Boolean> {
    return this.allExtended<Authenticate>(
        mustSatisfy = { token ->
            val tokens = token.credential.overlays.filterIsInstance<TokenBasedAuth>()
            val isSameToken = tokens.all { it.token == token.credential }
            QueryTree(value = isSameToken, node = token)
        }
    )
}

/**
 * Checks if there is a data flow from the
 * [de.fraunhofer.aisec.openstack.concepts.auth.ExtendedRequestContext.token] into the
 * [de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth].
 */
fun TranslationResult.hasDataFlowToToken(): QueryTree<Boolean> {
    return this.allExtended<ExtendedRequestContext>(
        mustSatisfy = { ctx ->
            val token = ctx.token
            if (
                token == null ||
                    ctx.userInfo?.userId == null ||
                    ctx.userInfo?.domainId == null ||
                    ctx.userInfo?.projectId == null
            ) {
                // If information is missing, we cannot determine the data flows and want to fail
                QueryTree(false, node = ctx, stringRepresentation = "Invalid Request context")
            } else {
                dataFlow(
                    // We start from the token in the request context
                    startNode = token,
                    // We want to find out which data can flow there, so we follow the data flow
                    // backwards
                    direction = Backward(GraphToFollow.DFG),
                    // All paths must lead to a TokenBasedAuth because otherwise, we detected a path
                    // which uses another token which was not used in the authentication.
                    type = Must,
                    predicate = { token ->
                        token.overlays.filterIsInstance<TokenBasedAuth>().isNotEmpty()
                    },
                )
            }
        }
    )
}
