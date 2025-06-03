/*
 * This file is part of the OpenStack Checker
 */
package http

import analyze
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpClient
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.operationNodes
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertNotNull

class HttpBarbicanClientPassTest {
    @Test
    fun barbicanClientPassTest() {
        val topLevel = Path("../external")
        val result = analyze(listOf(), topLevel, true)
        assertNotNull(result)

        val clients = result.conceptNodes.filterIsInstance<HttpClient>()
        assertNotNull(clients, "There should be HttpClient nodes")

        val requests = result.operationNodes.filterIsInstance<HttpRequest>()
        assertNotNull(requests, "There should be HttpRequest nodes")
    }
}
