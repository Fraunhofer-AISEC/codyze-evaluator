/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept
import de.fraunhofer.aisec.cpg.graph.concepts.newOperation

/**
 * Creates a new [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization] concept.
 */
fun de.fraunhofer.aisec.cpg.graph.MetadataProvider.newAuthorization(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node,
    policy: Policy,
    connect: Boolean,
) =
    newConcept(
        { AuthorizationWithPolicy(policy = policy) },
        underlyingNode = underlyingNode,
        connect = connect,
    )

/**
 * Creates a new [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization] concept to
 *   associate the operation with.
 * @param action The action to use for authorization.
 * @param targets The set of target nodes for the operation.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [Authorize] operation.
 */
fun de.fraunhofer.aisec.cpg.graph.MetadataProvider.newAuthorize(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node,
    concept: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization,
    action: de.fraunhofer.aisec.cpg.graph.Node,
    targets: Set<de.fraunhofer.aisec.cpg.graph.Node>,
    exception: de.fraunhofer.aisec.cpg.graph.Node,
    connect: Boolean,
) =
    newOperation(
        { concept ->
            Authorize(concept = concept, action = action, targets = targets, exception = exception)
        },
        underlyingNode = underlyingNode,
        concept = concept,
        connect = connect,
    )
