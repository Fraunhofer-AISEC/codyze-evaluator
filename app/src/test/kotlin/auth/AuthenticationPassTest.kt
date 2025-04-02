/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.ini.IniFileLanguage
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.openstack.passes.*
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertNotNull
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
        assertNotNull(result)
    }
}
