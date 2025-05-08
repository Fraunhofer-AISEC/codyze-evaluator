/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept
import de.fraunhofer.aisec.cpg.graph.concepts.newOperation

/**
 * Creates a new [Authorization] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param connect If `true`, the created [Concept] will be connected to the underlying node by
 *   setting its `underlyingNode`.
 * @return The created [Authorization] concept.
 */
fun MetadataProvider.newAuthorization(underlyingNode: Node, connect: Boolean) =
    newConcept(::Authorization, underlyingNode = underlyingNode, connect = connect)

/**
 * Creates a new [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The [Authorization] concept to associate the operation with.
 * @param policy The [Policy] to use for authorization.
 * @param targets The list of target nodes for the operation.
 * @param connect If `true`, the created [Concept] will be connected to the underlying node by
 *   setting its `underlyingNode`.
 * @return The created [Authorize] operation.
 */
fun MetadataProvider.newAuthorize(
    underlyingNode: Node,
    concept: Authorization,
    policy: Policy,
    targets: List<Node>,
    connect: Boolean,
) =
    newOperation(
        { concept -> Authorize(concept = concept, policy = policy, targets = targets) },
        underlyingNode = underlyingNode,
        concept = concept,
        connect = connect,
    )
