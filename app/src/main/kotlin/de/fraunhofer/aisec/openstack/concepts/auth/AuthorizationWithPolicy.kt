/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization

class AuthorizationWithPolicy(underlyingNode: Node? = null, val policy: Policy) :
    Authorization(underlyingNode = underlyingNode)

/** Represents a common abstract class for authorization operations. */
abstract class AuthorizationOperation(underlyingNode: Node? = null, concept: Concept) :
    Operation(underlyingNode = underlyingNode, concept)

/**
 * Represents an [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The associated [Authorization] concept.
 * @param action The action used for authorization.
 * @param targets A set of nodes representing the target of the action. This typically includes
 *   fields such as `project_id` and `user_id`.
 */
open class Authorize(
    underlyingNode: Node? = null,
    concept: Authorization,
    val action: Node,
    val targets: Set<Node>,
) : AuthorizationOperation(underlyingNode = underlyingNode, concept = concept)
