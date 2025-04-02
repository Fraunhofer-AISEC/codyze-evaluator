/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.allChildrenWithOverlays
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class AuthenticationPassTest {
    @Test
    fun authenticationPass() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerLanguage<IniFileLanguage>()
                it.registerPass<IniFileConfigurationSourcePass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpPecanLibPass>()
                it.registerPass<HttpWsgiPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("../external/webob")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder/api").toFile()),
                        "barbican" to listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                        "keystonemiddleware" to
                            listOf(
                                Path("../external/keystonemiddleware/keystonemiddleware").toFile()
                            ),
                        "conf" to listOf(topLevel.resolve("conf").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "barbican" to topLevel.resolve("barbican").toFile(),
                        "keystonemiddleware" to Path("../external/keystonemiddleware").toFile(),
                        "conf" to topLevel.resolve("conf").toFile(),
                    )
                )
            }

        val tokenBasedAuths = result.conceptNodes.filterIsInstance<TokenBasedAuth>()
        assertNotNull(tokenBasedAuths, "At least one TokenBasedAuth concept should be created")

        val cinderComponent = result.components.singleOrNull { it.name.localName == "cinder" }
        val cinderEndpoints = cinderComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(cinderEndpoints)
        cinderEndpoints.forEach { endpoint ->
            assertNotNull(
                endpoint.authentication,
                "Cinder HTTP endpoint should have authentication set",
            )
            assertTrue(
                endpoint.authentication is TokenBasedAuth,
                "Cinder HTTP endpoint authentication should be a TokenBasedAuth",
            )
        }

        val barbicanComponent = result.components.singleOrNull { it.name.localName == "barbican" }
        val barbicanEndpoints = barbicanComponent.allChildrenWithOverlays<HttpEndpoint>()
        assertNotNull(barbicanEndpoints)
        barbicanEndpoints.forEach { endpoint ->
            assertNotNull(
                endpoint.authentication,
                "Cinder HTTP endpoint should have authentication set",
            )
            assertTrue(
                endpoint.authentication is TokenBasedAuth,
                "Cinder HTTP endpoint authentication should be a TokenBasedAuth",
            )
        }
    }
}
