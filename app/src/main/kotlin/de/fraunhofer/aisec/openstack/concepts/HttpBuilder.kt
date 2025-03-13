/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.NodeBuilder
import de.fraunhofer.aisec.cpg.graph.codeAndLocationFrom
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpClient
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequestHandler
import de.fraunhofer.aisec.cpg.graph.concepts.http.RegisterHttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration

fun MetadataProvider.newHttpRequestHandler(
    underlyingNode: Node,
    basePath: String,
    endpoints: MutableList<HttpEndpoint> = mutableListOf(),
): HttpRequestHandler {
    val handler =
        HttpRequestHandler(
            underlyingNode = underlyingNode,
            basePath = basePath,
            endpoints = endpoints,
        )
    handler.underlyingNode = underlyingNode
    handler.codeAndLocationFrom(underlyingNode)
    NodeBuilder.log(handler)
    return handler
}

fun MetadataProvider.newHttpEndpoint(
    underlyingNode: FunctionDeclaration,
    httpMethod: String,
    arguments: List<Node>,
    path: String,
    authentication: Authentication?,
): HttpEndpoint {
    val endpoint =
        HttpEndpoint(
            underlyingNode = underlyingNode,
            httpMethod = mapHttpMethod(httpMethod),
            path = path,
            arguments = arguments,
            authentication = authentication,
        )
    endpoint.underlyingNode = underlyingNode
    endpoint.codeAndLocationFrom(underlyingNode)
    NodeBuilder.log(endpoint)
    return endpoint
}

fun MetadataProvider.newRegisterHttpEndpoint(
    underlyingNode: Node,
    concept: Concept,
    httpEndpoint: HttpEndpoint,
): RegisterHttpEndpoint {
    val operation =
        RegisterHttpEndpoint(
            underlyingNode = underlyingNode,
            concept = concept,
            httpEndpoint = httpEndpoint,
        )
    operation.underlyingNode = underlyingNode
    operation.codeAndLocationFrom(underlyingNode)
    NodeBuilder.log(operation)
    return operation
}

fun MetadataProvider.newHttpClient(underlyingNode: Node, isTLS: Boolean = false): HttpClient {
    val client = HttpClient(underlyingNode = underlyingNode, isTLS = isTLS)
    client.underlyingNode = underlyingNode
    client.codeAndLocationFrom(underlyingNode)
    NodeBuilder.log(client)
    return client
}

fun MetadataProvider.newHttpRequest(
    underlyingNode: Node,
    url: String,
    httpMethod: String,
    arguments: List<Node>,
    httpClient: HttpClient,
): HttpRequest {
    val request =
        HttpRequest(
            underlyingNode = underlyingNode,
            url = url,
            arguments = arguments,
            httpMethod = mapHttpMethod(httpMethod),
            concept = httpClient,
        )
    request.underlyingNode = underlyingNode
    request.codeAndLocationFrom(underlyingNode)

    httpClient.ops += request

    NodeBuilder.log(request)
    return request
}

fun mapHttpMethod(methodName: String): HttpMethod {
    return when (methodName.uppercase()) {
        "GET",
        "_GET",
        "SHOW" -> HttpMethod.GET
        "POST",
        "_CREATE",
        "CREATE" -> HttpMethod.POST
        "PUT",
        "_UPDATE",
        "UPDATE" -> HttpMethod.PUT
        "DELETE",
        "_DELETE" -> HttpMethod.DELETE
        "PATCH" -> HttpMethod.PATCH
        "OPTIONS" -> HttpMethod.OPTIONS
        "HEAD" -> HttpMethod.HEAD
        "CONNECT" -> HttpMethod.CONNECT
        "TRACE" -> HttpMethod.TRACE
        // TODO(lshala): Change this to unknown
        else -> HttpMethod.GET
    }
}
