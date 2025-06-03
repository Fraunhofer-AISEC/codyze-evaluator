/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept
import de.fraunhofer.aisec.cpg.graph.concepts.newOperation
import kotlin.apply

/**
 * Creates a new [ExtendedRequestContext] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param token An optional token node.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [ExtendedRequestContext] concept.
 */
fun de.fraunhofer.aisec.cpg.graph.MetadataProvider.newRequestContext(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node,
    token: de.fraunhofer.aisec.cpg.graph.Node? = null,
    connect: Boolean,
) =
    newConcept(
        { ExtendedRequestContext(underlyingNode, token) },
        underlyingNode = underlyingNode,
        connect = connect,
    )

/**
 * Creates a new [UserInfo] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The [ExtendedRequestContext] to associate the user info with.
 * @param userId The user ID node.
 * @param projectId The project ID node.
 * @param roles The roles node.
 * @param systemScope The system scope node.
 * @param domainId The domain ID node.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created `UserInfo` concept.
 */
fun de.fraunhofer.aisec.cpg.graph.MetadataProvider.newUserInfo(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node,
    concept: ExtendedRequestContext,
    userId: de.fraunhofer.aisec.cpg.graph.Node,
    projectId: de.fraunhofer.aisec.cpg.graph.Node,
    roles: de.fraunhofer.aisec.cpg.graph.Node,
    systemScope: de.fraunhofer.aisec.cpg.graph.Node,
    domainId: de.fraunhofer.aisec.cpg.graph.Node,
    connect: Boolean,
) =
    newConcept(
            { UserInfo(underlyingNode, userId, projectId, roles, systemScope, domainId) },
            underlyingNode = underlyingNode,
            connect = connect,
        )
        .apply { concept.userInfo = this }

/**
 * Creates a new [PopulateUserInfo] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The [UserInfo] concept to associate the operation with.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [PopulateUserInfo] operation.
 */
fun de.fraunhofer.aisec.cpg.graph.MetadataProvider.newPopulateUserInfo(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node,
    concept: UserInfo,
    connect: Boolean,
) =
    newOperation(
        { concept -> PopulateUserInfo(userInfo = concept) },
        underlyingNode = underlyingNode,
        concept = concept,
        connect = connect,
    )
