/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.query.and
import de.fraunhofer.aisec.cpg.query.or
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import de.fraunhofer.aisec.openstack.queries.authentication.doNotRequireOrHaveTokenBasedAuthentication
import de.fraunhofer.aisec.openstack.queries.authentication.endpointsAreAuthenticated
import de.fraunhofer.aisec.openstack.queries.authentication.useKeystoneForAuthentication
import kotlin.io.path.Path
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AuthenticationPassTest {
    @Test
    fun testAuthenticationPass() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers", "sqlalchemy")
                it.includePath("../external/oslo.context")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder").toFile()),
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
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("../external/oslo.context")
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

        val r = endpointsAreAuthenticated(result)
        assertTrue(r.value)
        println(r.printNicely())
    }

    @Test
    fun testAuthStrategyProvider() {
        val topLevel = Path("../projects/multi-tenancy/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "conf" to topLevel.resolve("conf").toFile(),
                        "cinder" to topLevel.resolve("cinder/api").toFile(),
                        "barbican" to topLevel.resolve("barbican/api").toFile(),
                    )
                )
            }

        assertNotNull(result)

        val query = useKeystoneForAuthentication(result)
        println(query.printNicely())
        assertEquals(true, query.value)
    }

    @Test
    fun testTokenBasedAuthentication() {
        val topLevel = Path("../projects/multi-tenancy/components")
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

        // Is a valid token provider configured?
        val r = doNotRequireOrHaveTokenBasedAuthentication(result)
        assertTrue(r.value)
        println(r.printNicely())
    }
}
