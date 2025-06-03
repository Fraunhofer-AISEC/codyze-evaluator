/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.auth.RequestContext

/**
 * Represents a request context. It is an inheritance of
 * [de.fraunhofer.aisec.cpg.graph.concepts.auth.RequestContext]
 *
 * @param underlyingNode The underlying CPG node.
 * @param token The token.
 */
open class ExtendedRequestContext(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val token: de.fraunhofer.aisec.cpg.graph.Node? = null,
) : de.fraunhofer.aisec.cpg.graph.concepts.auth.RequestContext(underlyingNode = underlyingNode) {
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
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val userId: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val projectId: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val roles: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val systemScope: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val domainId: de.fraunhofer.aisec.cpg.graph.Node? = null,
) : de.fraunhofer.aisec.cpg.graph.concepts.Concept(underlyingNode = underlyingNode)

/**
 * Abstract base class for user info operations.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The associated concept.
 */
abstract class UserInfoOperation(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?,
    concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept,
) :
    de.fraunhofer.aisec.cpg.graph.concepts.Operation(
        underlyingNode = underlyingNode,
        concept = concept,
    )

/**
 * Represents an operation to populate user info.
 *
 * @param underlyingNode The underlying CPG node.
 * @param userInfo The user info to populate.
 */
open class PopulateUserInfo(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    var userInfo: UserInfo,
) : UserInfoOperation(underlyingNode = underlyingNode, concept = userInfo)
