/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization

/** Represents a common abstract class for authorization operations. */
abstract class AuthorizationOperation(underlyingNode: Node? = null, concept: Concept) :
    Operation(underlyingNode = underlyingNode, concept)

/**
 * Represents an [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The associated [Authorization] concept.
 * @param policy The [Policy] used for authorization.
 * @param targets A list of nodes representing the target of the action. This typically includes
 *   fields such as `project_id` and `user_id`.
 */
class Authorize(
    underlyingNode: Node? = null,
    concept: Authorization,
    val policy: Policy,
    val targets: List<Node>,
) : AuthorizationOperation(underlyingNode = underlyingNode, concept = concept)
