/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.*
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.technology.openstack.*
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.concepts.*
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
}
