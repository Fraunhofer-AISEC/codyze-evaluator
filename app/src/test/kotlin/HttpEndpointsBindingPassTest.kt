/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.operationNodes
import de.fraunhofer.aisec.openstack.passes.http.HttpCinderClientPass
import de.fraunhofer.aisec.openstack.passes.http.HttpEndpointsBindingPass
import de.fraunhofer.aisec.openstack.passes.http.HttpWsgiPass
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class HttpEndpointsBindingPassTest {
    @Test
    fun testHttpEndpointsBinding() {
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
                        "cinder" to
                            listOf(
                                topLevel.resolve("cinder/cinder/api/openstack/wsgi.py").toFile(),
                                topLevel.resolve("cinder/cinder/api/extensions.py").toFile(),
                                topLevel.resolve("cinder/cinder/api/v3/router.py").toFile(),
                                topLevel
                                    .resolve("cinder/cinder/api/v3/volume_metadata.py")
                                    .toFile(),
                                topLevel
                                    .resolve("cinder/cinder/api/contrib/volume_actions.py")
                                    .toFile(),
                            ),
                        "python-cinderclient" to
                            listOf(
                                topLevel
                                    .resolve("python-cinderclient/cinderclient/base.py")
                                    .toFile(),
                                topLevel
                                    .resolve("python-cinderclient/cinderclient/v3/volumes_base.py")
                                    .toFile(),
                                topLevel
                                    .resolve("python-cinderclient/cinderclient/v3/volumes.py")
                                    .toFile(),
                            ),
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

        val requests = result.operationNodes.filterIsInstance<HttpRequest>()
        assertNotNull(requests, "There should be HttpRequest nodes")

        val endpoints = result.conceptNodes.filterIsInstance<HttpEndpoint>()
        assertNotNull(endpoints, "There should be HttpEndpoint nodes")

        // Test matching endpoints with different parameters
        val request =
            requests.firstOrNull() {
                it.url == "/v3/volumes/{volume}/metadata" && it.httpMethod == HttpMethod.PUT
            }
        assertNotNull(request)
        val endpoint = request.to.singleOrNull()
        assertNotNull(endpoint)

        assertEquals(request.httpMethod, endpoint.httpMethod)
        assertEquals("/v3/volumes/{volume_id}/metadata", endpoint.path)

        // Test action endpoints
        val actionRequest =
            requests.firstOrNull() {
                it.url == "/v3/volumes/{volume}/action" && it.httpMethod == HttpMethod.POST
            }
        assertNotNull(actionRequest)
        val actionEndpoint = actionRequest.to.singleOrNull()
        assertNotNull(actionEndpoint)
        assertEquals(actionRequest.httpMethod, actionEndpoint.httpMethod)

        val requestBodyValue = actionRequest.arguments.firstOrNull()?.evaluate() as? String
        assertNotNull(requestBodyValue)

        val actionAnnotation =
            actionEndpoint.underlyingNode?.annotations?.firstOrNull {
                it.name.localName == "action"
            }
        assertNotNull(actionAnnotation)
        val annotationValue = actionAnnotation.members.firstOrNull()?.value?.evaluate() as? String
        assertNotNull(annotationValue)
        assertEquals(requestBodyValue, annotationValue)
    }
}
