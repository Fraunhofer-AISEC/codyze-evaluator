/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.*
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.technology.openstack.Cinder
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.*
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.query.*
import kotlin.io.path.Path
import kotlin.test.*
import org.junit.jupiter.api.Test

class AuthenticationPassTest {
    @Test
    fun testAuthenticationPass() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<PreAuthorizationPass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to listOf(topLevel.resolve("cinder/cinder").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican").toFile()),
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
        with(result) {
            val query = useKeystoneForAuthentication()
            println(query.printNicely())
            assertEquals(true, query.value)
        }
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

        with(result) {
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
