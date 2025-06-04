/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.http.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.HttpWsgiPass
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import kotlin.io.path.Path
import kotlin.test.*

/**
 * Test suite for the [HttpEndpointsBindingPass], which analyzes OpenStack [HttpEndpoint]s and binds
 * them to [HttpRequest]s.
 */
class HttpEndpointsBindingPassTest {

    /**
     * Test case to verify that the [HttpEndpointsBindingPass] correctly binds [HttpRequest]s from
     * [PythonCinderClient] to [HttpEndpoint]s in [Cinder].
     */
    @Test
    fun testHttpEndpointsBinding() {
        val topLevel = Path("external/")
        val result =
            analyze(files = listOf(), topLevel = topLevel, usePasses = true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<HttpCinderClientPass>()
                it.registerPass<HttpWsgiPass>()
                it.registerPass<HttpEndpointsBindingPass>()
                it.exclusionPatterns("tests", "drivers")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to
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
                        PythonCinderClient.name to
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
                        Cinder.name to topLevel.resolve("cinder").toFile(),
                        PythonCinderClient.name to
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
