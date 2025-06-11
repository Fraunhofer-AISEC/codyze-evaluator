/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.authentication

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.query.*

/**
 * The list of valid token providers that are considered to be valid for all project. It is the
 * default parameter used in [isTokenProviderConfigured].
 *
 * Note: Projects might have different valid token providers, so a customized list should be
 * provided to [isTokenProviderConfigured] and [tokenBasedAuthenticationWhenRequired] when
 * necessary.
 */
val defaultValidTokenProvider = setOf("jws", "jwt")

/**
 * Determines if the [de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint] [this] does not
 * require authentication.
 *
 * Note: This whitelist has to be customized for each project.
 */
fun HttpEndpoint.doesNotNeedAuthentication(
    requiresAuthentication: HttpEndpoint.() -> Boolean
): QueryTree<Boolean> {
    // Checks if the endpoint is in the list of endpoints that do not require authentication.
    val doesNotNeedAuth = !requiresAuthentication(this)

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
 * Checks if the [TranslationResult] contains a [ConfigurationSource] that configures that the
 * provider is considered to be a [validTokenProvider].
 *
 * @param validTokenProvider The list of valid token providers that are considered to be valid for
 *   the project.
 */
context(TranslationResult)
fun isTokenProviderConfigured(
    validTokenProvider: Set<String> = defaultValidTokenProvider
): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.existsExtended<ConfigurationSource>(
        sel = { config -> config.name.toString() == "keystone.conf" },
        mustSatisfy = { config ->
            val providerGroups =
                config.groups.flatMap { group ->
                    group.options.filter { it.name.localName == "provider" }
                }

            val configuresTokenAuth =
                providerGroups.singleOrNull { it.evaluate().toString() in validTokenProvider } !=
                    null

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
 * Checks if the [HttpEndpoint] [this] requires token-based authentication. The attribute
 * [HttpEndpoint.authentication] is set by the pass only if a token provider has been configured.
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
 * Checks if all [HttpEndpoint]s in the [TranslationResult] are either in the list of endpoints that
 * do not require authentication (i.e. not in the list of [requiresAuthentication]) or have a valid
 * (in terms of secure) token-based authentication in-place.
 */
context(TranslationResult)
fun tokenBasedAuthenticationWhenRequired(
    requiresAuthentication: HttpEndpoint.() -> Boolean,
    validTokenProvider: Set<String> = defaultValidTokenProvider,
): QueryTree<Boolean> {
    val tr = this@TranslationResult
    // Is a valid token provider configured?
    val tokenProviderConfigured = isTokenProviderConfigured(validTokenProvider)

    return tr.allExtended<HttpEndpoint>(
        mustSatisfy = { endpoint ->
            // The requirement is satisfied if the endpoint has token-based authentication enabled
            // and a valid token provider is configured or if the endpoint does not need
            // authentication.
            (tokenProviderConfigured and endpoint.hasTokenBasedAuth()) or
                endpoint.doesNotNeedAuthentication(requiresAuthentication)
        }
    )
}

/**
 * Checks if any [Authenticate] uses a [TokenBasedAuth] where the token is equal to the credential
 * of that [Authenticate].
 */
context(TranslationResult)
fun usesSameTokenAsCredential(): QueryTree<Boolean> {
    val tr = this@TranslationResult
    return tr.allExtended<Authenticate>(
        mustSatisfy = { token ->
            val tokens = token.credential.overlays.filterIsInstance<TokenBasedAuth>()
            val isSameToken = tokens.all { it.token == token.credential }
            QueryTree(value = isSameToken, node = token)
        }
    )
}
