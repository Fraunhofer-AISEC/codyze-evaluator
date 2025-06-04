/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack.passes.http

import de.fraunhofer.aisec.codyze.concepts.mapHttpMethod
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.firstParentOrNull
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.graph.statements.expressions.BinaryOperator
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.EOGStarterPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

/**
 * Pass for analyzing `python-cinderclient` to extract and register HTTP requests. It identifies the
 * base `Manager` class, which holds the common CRUD methods, and traces where these methods are
 * called to extract the endpoints.
 */
@DependsOn(SymbolResolver::class)
class HttpCinderClientPass(ctx: TranslationContext) : EOGStarterPass(ctx) {
    val apiVersionPath = "/v3"

    override fun accept(node: Node) {
        when (node) {
            is MethodDeclaration -> {
                val crudMethods = setOf("_create", "_get", "_update", "_delete")
                if (
                    node.name.localName in crudMethods &&
                        node.recordDeclaration?.name?.localName == "Manager"
                ) {
                    // Get all calls that are invoked by the Manager.
                    for (memberCall in node.calledBy) {
                        registerRequests(memberCall)
                    }
                }
            }
        }
    }

    /**
     * Registers an HttpRequest for the given [CallExpression]. Identifies the associated
     * [HttpClient] or creates a new one if none exists. Additionally, checks for `_action` methods
     * within the class to register the `/action` requests.
     */
    private fun registerRequests(memberCall: CallExpression) {
        val record = memberCall.astParent?.firstParentOrNull<RecordDeclaration>()
        if (record != null) {
            val httpClient =
                record.conceptNodes.filterIsInstance<HttpClient>().singleOrNull()
                    ?: newHttpClient(record, isTLS = false, authentication = null, connect = true)
            val extractedPath = extractEndpointPath(memberCall.arguments.first())
            val path = if (extractedPath != null) "$apiVersionPath$extractedPath" else ""

            newHttpRequest(
                underlyingNode = memberCall,
                url = path,
                httpMethod = mapHttpMethod(memberCall.name.localName),
                arguments = memberCall.arguments,
                concept = httpClient,
                connect = true,
            )

            val actionMethod = record.methods.firstOrNull() { it.name.localName == "_action" }
            if (actionMethod != null) {
                // When the action method exists, we go through all invoked calls within the class
                // and register the
                // request
                registerActionRequests(method = actionMethod, httpClient = httpClient)
            }
        }
    }

    /**
     * Extracts the URL from the action method and registers all calls within this class that invoke
     * it.
     */
    private fun registerActionRequests(method: MethodDeclaration, httpClient: HttpClient) {
        val postCall = method.calls["post"]
        val pathArg = postCall?.arguments?.firstOrNull()
        if (pathArg != null) {
            val extractedPath = extractEndpointPath(pathArg)
            val path = if (extractedPath != null) "$apiVersionPath$extractedPath" else ""
            for (calls in method.calledBy) {
                val httpMethod = HttpMethod.POST
                newHttpRequest(
                    underlyingNode = calls,
                    url = path,
                    httpMethod = mapHttpMethod(httpMethod.toString()),
                    arguments = calls.arguments,
                    concept = httpClient,
                    connect = true,
                )
            }
        }
    }

    /** Extracts the endpoint path from the given [Node]. */
    private fun extractEndpointPath(node: Node): String? {
        val apiEndpoint =
            when (val endpoint = node) {
                is Literal<*> -> endpoint.evaluate() as? String
                is BinaryOperator -> endpoint.evaluate(EndpointValueEvaluator()) as? String
                is Reference -> {
                    endpoint.evaluate(EndpointValueEvaluator()) as? String
                }

                else -> null
            }
        return apiEndpoint
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
