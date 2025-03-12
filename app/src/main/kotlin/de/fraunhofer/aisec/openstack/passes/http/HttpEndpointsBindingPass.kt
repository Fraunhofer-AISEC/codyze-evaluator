/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.http

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.operationNodes
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

@DependsOn(SymbolResolver::class)
@DependsOn(HttpCinderClientPass::class)
@DependsOn(HttpWsgiPass::class)
class HttpEndpointsBindingPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        val requests = t.operationNodes.filterIsInstance<HttpRequest>()
        val endpoints = t.conceptNodes.filterIsInstance<HttpEndpoint>()

        for (request in requests) {
            val matchingEndpoint =
                endpoints.find { endpoint ->
                    request.httpMethod == endpoint.httpMethod &&
                        compareApiEndpoints(request.url, endpoint.path)
                }

            matchingEndpoint?.let { endpoint ->
                if (endpoint.path.endsWith("/action")) {
                    val requestBody = request.arguments.firstOrNull()
                    requestBody?.let {
                        when (it) {
                            is Literal<*> -> it.evaluate() as? String
                        }
                    }
                    val methodName = endpoint.underlyingNode
                    methodName?.name?.localName

                    if (requestBody != null && methodName != null && requestBody == methodName) {
                        request.to.add(endpoint)
                    }
                } else {
                    request.to.add(endpoint)
                }
            }
        }
    }

    private fun compareApiEndpoints(apiEndpoint1: String, apiEndpoint2: String): Boolean {
        // Return true if the endpoints are exactly the same
        if (apiEndpoint1 == apiEndpoint2) return true

        // Compares two API endpoints by ignoring the content of the parameters (e.g., {any_id})
        // and checking their structure.
        return apiEndpoint1.split(Regex("\\{[^/]+}")) == apiEndpoint2.split(Regex("\\{[^/]+}"))
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
