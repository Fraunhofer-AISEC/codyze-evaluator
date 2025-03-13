/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts

import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod

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
