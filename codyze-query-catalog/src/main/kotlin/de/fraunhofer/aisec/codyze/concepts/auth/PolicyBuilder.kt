/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.*
import kotlin.apply

/**
 * Creates a new [Policy] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param connect @param connect If `true`, the created [Concept] will be connected to the
 *   underlying node by setting its `underlyingNode`..
 * @return The created [Policy] concept.
 */
fun MetadataProvider.newPolicy(underlyingNode: Node, connect: Boolean) =
    newConcept(::Policy, underlyingNode = underlyingNode, connect = connect)

/**
 * Creates a new [PolicyRule] concept.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The `Policy` to associate the rule with.
 * @param roles The roles for the policy rule.
 * @param connect If `true`, the created [Concept] will be connected to the underlying node by
 *   setting its `underlyingNode`.
 * @return The created [PolicyRule] concept.
 */
fun MetadataProvider.newPolicyRule(
    underlyingNode: Node,
    concept: Policy,
    roles: Set<Role>,
    connect: Boolean,
) =
    newConcept({ PolicyRule(roles = roles) }, underlyingNode = underlyingNode, connect = connect)
        .apply { concept.rule = this }
