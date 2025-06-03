/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.RequestContext

/**
 * Represents a request context. It is an inheritance of [RequestContext]
 *
 * @param underlyingNode The underlying CPG node.
 * @param token The token.
 */
open class ExtendedRequestContext(underlyingNode: Node? = null, val token: Node? = null) :
    RequestContext(underlyingNode = underlyingNode) {
    var userInfo: UserInfo? = null
}

/**
 * Represents user information in a request context.
 *
 * @param underlyingNode The underlying CPG node.
 * @param userId The user ID.
 * @param projectId The project ID.
 * @param roles The roles.
 * @param systemScope The system scope.
 * @param domainId The domain ID.
 */
open class UserInfo(
    underlyingNode: Node? = null,
    val userId: Node? = null,
    val projectId: Node? = null,
    val roles: Node? = null,
    val systemScope: Node? = null,
    val domainId: Node? = null,
) : Concept(underlyingNode = underlyingNode)

/**
 * Abstract base class for user info operations.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The associated concept.
 */
abstract class UserInfoOperation(underlyingNode: Node?, concept: Concept) :
    Operation(underlyingNode = underlyingNode, concept = concept)

/**
 * Represents an operation to populate user info.
 *
 * @param underlyingNode The underlying CPG node.
 * @param userInfo The user info to populate.
 */
open class PopulateUserInfo(underlyingNode: Node? = null, var userInfo: UserInfo) :
    UserInfoOperation(underlyingNode = underlyingNode, concept = userInfo)
