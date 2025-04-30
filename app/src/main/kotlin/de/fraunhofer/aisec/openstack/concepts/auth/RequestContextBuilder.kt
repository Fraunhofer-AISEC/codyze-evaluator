/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept
import de.fraunhofer.aisec.cpg.graph.concepts.newOperation

fun MetadataProvider.newRequestContext(
    underlyingNode: Node,
    token: Node? = null,
    connect: Boolean,
) =
    newConcept(
        { RequestContext(underlyingNode, token) },
        underlyingNode = underlyingNode,
        connect = connect,
    )

fun MetadataProvider.newUserInfo(
    underlyingNode: Node,
    concept: RequestContext,
    userId: Node,
    projectId: Node,
    roles: Node,
    systemScope: Node,
    domainId: Node,
    connect: Boolean,
) =
    newConcept(
            { UserInfo(underlyingNode, userId, projectId, roles, systemScope, domainId) },
            underlyingNode = underlyingNode,
            connect = connect,
        )
        .apply { concept.userInfo = this }

fun MetadataProvider.newPopulateUserInfo(
    underlyingNode: Node,
    concept: UserInfo,
    connect: Boolean,
) =
    newOperation(
        { concept -> PopulateUserInfo(userInfo = concept) },
        underlyingNode = underlyingNode,
        concept = concept,
        connect = connect,
    )
