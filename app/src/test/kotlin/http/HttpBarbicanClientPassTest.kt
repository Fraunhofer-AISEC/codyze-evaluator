/*
 * This file is part of the OpenStack Checker
 */
package http

import analyze
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpClient
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.operationNodes
import de.fraunhofer.aisec.openstack.passes.http.HttpBarbicanClientPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull

class HttpBarbicanClientPassTest {
    @Test
    fun barbicanClientPassTest() {
        val topLevel = Path("../external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<HttpBarbicanClientPass>()
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf(
                        "python-barbicanclient" to
                            listOf(
                                topLevel.resolve("python-barbicanclient/barbicanclient").toFile()
                            ),
                        "keystoneauth" to
                            listOf(topLevel.resolve("keystoneauth/keystoneauth1").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        "python-barbicanclient" to
                            topLevel.resolve("python-barbicanclient").toFile(),
                        "keystoneauth" to topLevel.resolve("keystoneauth").toFile(),
                    )
                )
            }
        assertNotNull(result)

        val clients = result.conceptNodes.filterIsInstance<HttpClient>()
        assertNotNull(clients, "There should be HttpClient nodes")

        val requests = result.operationNodes.filterIsInstance<HttpRequest>()
        assertNotNull(requests, "There should be HttpRequest nodes")
    }
}
