/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.graph.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept
import de.fraunhofer.aisec.cpg.graph.concepts.newOperation
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Expression

/**
 * Creates a new [Authorization] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [Authorization] concept.
 */
fun MetadataProvider.newAuthorization(
    underlyingNode: Node,
    policy: Policy,
    policyRef: Expression,
    connect: Boolean,
) =
    newConcept(
        { AuthorizationWithPolicy(policy = policy, policyRef = policyRef) },
        underlyingNode = underlyingNode,
        connect = connect,
    )

/**
 * Creates a new [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The [Authorization] concept to associate the operation with.
 * @param action The action to use for authorization.
 * @param targets The set of target nodes for the operation.
 * @param connect If `true`, the created [de.fraunhofer.aisec.cpg.graph.concepts.Concept] will be
 *   connected to the underlying node by setting its `underlyingNode`.
 * @return The created [Authorize] operation.
 */
fun MetadataProvider.newAuthorize(
    underlyingNode: Node,
    concept: Authorization,
    action: Node,
    targets: Set<Node>,
    exception: Node,
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
