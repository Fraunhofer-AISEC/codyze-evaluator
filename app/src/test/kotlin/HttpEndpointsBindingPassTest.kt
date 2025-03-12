/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.openstack.passes.http.HttpCinderClientPass
import de.fraunhofer.aisec.openstack.passes.http.HttpEndpointsBindingPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull

class HttpEndpointsBindingPassTest {
    @Test
    fun checkRegistration() {
        val topLevel = Path("../external/")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true, persistNeo4j = false) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<HttpCinderClientPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<HttpEndpointsBindingPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        "cinder" to listOf(topLevel.resolve("cinder/cinder").toFile()),
                        "python-cinderclient" to
                            listOf(topLevel.resolve("python-cinderclient/cinderclient").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "cinder" to topLevel.resolve("cinder").toFile(),
                        "python-cinderclient" to
                            topLevel.resolve("python-cinderclient/cinderclient").toFile(),
                    )
                )
            }
        assertNotNull(result)
    }
}
