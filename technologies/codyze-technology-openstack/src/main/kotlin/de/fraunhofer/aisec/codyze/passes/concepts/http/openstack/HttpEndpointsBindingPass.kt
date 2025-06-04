/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.http.openstack

import de.fraunhofer.aisec.codyze.passes.concepts.http.python.HttpWsgiPass
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.getAnnotation
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

/**
 * Pass for binding HTTP requests to their corresponding endpoints in [Cinder]. This pass identifies
 * HTTP requests and matches them with defined endpoints based on the HTTP method.
 */
@DependsOn(SymbolResolver::class)
@DependsOn(HttpCinderClientPass::class)
@DependsOn(HttpBarbicanClientPass::class)
@DependsOn(HttpWsgiPass::class)
class HttpEndpointsBindingPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        val requests = t.operationNodes.filterIsInstance<HttpRequest>()
        val endpoints = t.conceptNodes.filterIsInstance<HttpEndpoint>()

        for (request in requests) {
            val matchingEndpoints =
                endpoints.filter { endpoint ->
                    request.httpMethod == endpoint.httpMethod &&
                        compareApiEndpoints(request.url, endpoint.path)
                }

            for (endpoint in matchingEndpoints) {
                if (endpoint.path.endsWith("/action")) {
                    // Extract the request body value, assuming the body might contain either
                    // the method name or the annotation value.
                    val requestBodyValue =
                        request.arguments.firstOrNull()?.let {
                            when (it) {
                                is Literal<*> -> it.evaluate() as? String
                                else -> null
                            }
                        } ?: continue
                    val method = endpoint.underlyingNode as? MethodDeclaration ?: continue
                    val actionName =
                        method.getAnnotation("action")?.members?.firstOrNull()?.value?.evaluate()
                            as? String

                    // Compare the request body with
                    // either the method name or the action annotation.
                    if (
                        actionName != null &&
                            (requestBodyValue == method.name.localName ||
                                requestBodyValue == actionName)
                    ) {
                        request.to.add(endpoint)
                    }
                } else {
                    // For non-action endpoints, just add the endpoint to the request.
                    request.to.add(endpoint)
                }
            }
        }
    }

    /**
     * Compares two API endpoints by ignoring the content of path parameters (e.g., `{any_id}`) and
     * checking their structure.
     */
    private fun compareApiEndpoints(apiEndpoint1: String, apiEndpoint2: String): Boolean {
        // Return true if the endpoints are exactly the same
        if (apiEndpoint1 == apiEndpoint2) return true
        return apiEndpoint1.split(Regex("\\{[^/]+}")) == apiEndpoint2.split(Regex("\\{[^/]+}"))
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
