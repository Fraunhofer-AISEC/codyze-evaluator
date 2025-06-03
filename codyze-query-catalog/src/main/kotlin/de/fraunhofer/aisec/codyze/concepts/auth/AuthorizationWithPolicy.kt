/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization

class AuthorizationWithPolicy(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val policy: Policy,
) : de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization(underlyingNode = underlyingNode)

/** Represents a common abstract class for authorization operations. */
abstract class AuthorizationOperation(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept,
) : de.fraunhofer.aisec.cpg.graph.concepts.Operation(underlyingNode = underlyingNode, concept)

/**
 * Represents an [Authorize] operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The associated [de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization]
 *   concept.
 * @param action The action used for authorization.
 * @param targets A set of nodes representing the target resource of the action. These nodes
 *   typically include identifiers such as `project_id` and `user_id`.
 */
open class Authorize(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    concept: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization,
    val action: de.fraunhofer.aisec.cpg.graph.Node,
    val targets: Set<de.fraunhofer.aisec.cpg.graph.Node>,
    val exception: de.fraunhofer.aisec.cpg.graph.Node,
) : AuthorizationOperation(underlyingNode = underlyingNode, concept = concept)

/**
 * Represents a domain scope check operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param rule The rule used for the domain scope check.
 */
open class CheckDomainScope(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    concept: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization,
    val rule: de.fraunhofer.aisec.cpg.graph.Node,
) : AuthorizationOperation(underlyingNode = underlyingNode, concept)
