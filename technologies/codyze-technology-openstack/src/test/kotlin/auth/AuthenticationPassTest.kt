/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.codyze.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.codyze.openstack.passes.http.HttpWsgiPass
import de.fraunhofer.aisec.codyze.passes.openstack.http.HttpPecanLibPass
import de.fraunhofer.aisec.codyze.queries.authentication.endpointsAreAuthenticated
import de.fraunhofer.aisec.codyze.queries.authentication.hasDataFlowToToken
import de.fraunhofer.aisec.codyze.queries.authentication.tokenBasedAuthenticationWhenRequired
import de.fraunhofer.aisec.codyze.queries.authentication.useKeystoneForAuthentication
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.assumptions.assume
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.existsExtended
import kotlin.io.path.Path
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AuthenticationPassTest {
    @Test
    fun testAuthenticationPass() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)

        val tokenBasedAuths = result.conceptNodes.filterIsInstance<TokenBasedAuth>()
        assertNotNull(tokenBasedAuths, "At least one TokenBasedAuth concept should be created")

        val cinderComponent = result.components.singleOrNull { it.name.localName == "cinder" }
        assertNotNull(cinderComponent)
        val cinderEndpoints = cinderComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(cinderEndpoints)
        cinderEndpoints.forEach { endpoint ->
            // Check that authentication is applied only to the /v3 endpoints
            if (endpoint.path.contains("/v3")) {
                assertNotNull(endpoint.authentication, "Endpoints should have authentication set")
                assertTrue(
                    endpoint.authentication is TokenBasedAuth,
                    "Authentication should be TokenBasedAuth",
                )
            } else {
                assertNull(
                    endpoint.authentication,
                    "Non 'v3' version endpoints should not have authentication set",
                )
            }
        }

        val barbicanComponent = result.components.singleOrNull { it.name.localName == "barbican" }
        assertNotNull(barbicanComponent)
        val barbicanEndpoints = barbicanComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(barbicanEndpoints)
        barbicanEndpoints.forEach { endpoint ->
            // Check that authentication is applied only to the /v1 endpoints
            if (endpoint.path.contains("/v1")) {
                assertNotNull(endpoint.authentication, "Endpoints should have authentication set")
                assertTrue(
                    endpoint.authentication is TokenBasedAuth,
                    "Authentication should be TokenBasedAuth",
                )
            } else {
                assertNull(
                    endpoint.authentication,
                    "Non 'v1' version endpoints should not have authentication set ",
                )
            }
        }
    }

    @Test
    fun testAllComponentEndpointsHaveAuthentication() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)

        assertNotNull(result)

        with(result) {
            val r = endpointsAreAuthenticated()
            assertTrue(r.value)
            println(r.printNicely())
        }
    }

    @Test
    fun testAuthStrategyProvider() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)

        assertNotNull(result)

        val query = useKeystoneForAuthentication(result)
        println(query.printNicely())
        assertEquals(true, query.value)
    }

    @Test
    fun testTokenBasedAuthentication() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                        "keystonemiddleware" to
                            listOf(
                                topLevel.resolve("keystonemiddleware/keystonemiddleware").toFile()
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "barbican" to topLevel.resolve("barbican").toFile(),
                        "keystonemiddleware" to topLevel.resolve("keystonemiddleware").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        assertNotNull(result)

        with<TranslationResult, Unit>(result) {
            // Is a valid token provider configured?
            val r = tokenBasedAuthenticationWhenRequired()
            assertTrue(r.value)
            println(r.printNicely())
        }
    }

    /**
     * Determines if the [HttpEndpoint] [this] does not require authentication.
     *
     * Note: This whitelist has to be customized for each project.
     */
    fun HttpEndpoint.doesNotNeedAuthentication(): QueryTree<Boolean> {
        // Currently, we assume that only the endpoints under "/v3" (for cinder) and "/v1" (for
        // barbican) need authentication.
        val doesNotNeedAuth =
            !((this.underlyingNode?.component?.name?.localName == "cinder" &&
                this.path.startsWith("/v3/")) ||
                (this.underlyingNode?.component?.name?.localName == "barbican" &&
                    this.path.startsWith("/v1/")))

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
     * Checks if the [TranslationResult] [this] contains a [ConfigurationSource] that configures
     * that the provider is a valid token provider.
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
                    providerGroups.singleOrNull { it.evaluate().toString() in tokenProvider } !=
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
     * The list of valid token providers that are valid for the project.
     *
     * Note: This set may change depending on the project or state-of-the-art.
     */
    val tokenProvider = setOf("fernet", "jws")

    /**
     * Checks if the [HttpEndpoint] [this] requires token-based authentication. The attribute
     * [HttpEndpoint.authentication] is set by the pass only if a token provider has been
     * configured.
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

    @Test
    fun testAccessToken() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)

        assertNotNull(result)
        with(result) {
            val q = usesSameTokenAsCredential() and hasDataFlowToToken()
            assertFalse(q.value)
        }
    }

    /**
     * Checks if any [Authenticate] uses a [TokenBasedAuth] where the token is equal to the
     * credential of that [Authenticate].
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
}
