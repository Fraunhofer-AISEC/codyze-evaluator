/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.openstack.passes.OsloConfigPass
import de.fraunhofer.aisec.openstack.passes.auth.AuthenticationPass
import de.fraunhofer.aisec.openstack.passes.auth.AuthorizationPass
import de.fraunhofer.aisec.openstack.passes.auth.OsloPolicyPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.assertNotNull
import org.junit.jupiter.api.Test

class AuthorizationPassTest {
    @Test
    fun authorizationPass() {
        val topLevel = Path("../projects/BYOK/components")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<AuthorizationPass>()
                it.registerPass<AuthenticationPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<OsloPolicyPass>()
                it.registerPass<ProvideConfigPass>()
                it.registerPass<OsloConfigPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("../external/webob")
                it.includePath("../external/oslo.config")
                it.includePath("../external/oslo.policy")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder").toFile())
                        //                        "barbican" to
                        // listOf(topLevel.resolve("barbican/barbican/api").toFile()),
                        //                        "keystonemiddleware" to
                        //                            listOf(
                        //
                        // Path("../external/keystonemiddleware/keystonemiddleware").toFile()
                        //                            ),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile()
                        //                        "barbican" to
                        // topLevel.resolve("barbican").toFile(),
                        //                        "keystonemiddleware" to
                        // Path("../external/keystonemiddleware").toFile(),
                    )
                )
            }
        assertNotNull(result)
    }
}
