/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.http.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.technology.openstack.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import kotlin.io.path.Path
import kotlin.test.*

/**
 * Test suite for the [HttpBarbicanClientPass], which analyzes the [PythonBarbicanClient] in
 * OpenStack to identify HTTP client and request nodes.
 */
class HttpBarbicanClientPassTest {

    /**
     * Test case to verify that the [HttpBarbicanClientPass] correctly identifies HTTP client and
     * request nodes (as [HttpClient] and [HttpRequest]) in the [PythonBarbicanClient] component.
     */
    @Test
    fun testBarbicanClientPass() {
        val topLevel = Path("../external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<HttpBarbicanClientPass>()
                it.exclusionPatterns("tests")
                it.softwareComponents(
                    mutableMapOf(
                        PythonBarbicanClient.name to
                            listOf(
                                topLevel.resolve("python-barbicanclient/barbicanclient").toFile()
                            ),
                        KeystoneAuth.name to
                            listOf(topLevel.resolve("keystoneauth/keystoneauth1").toFile()),
                    )
                )
                it.topLevels(
                    mapOf(
                        PythonBarbicanClient.name to
                            topLevel.resolve("python-barbicanclient").toFile(),
                        KeystoneAuth.name to topLevel.resolve("keystoneauth").toFile(),
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
