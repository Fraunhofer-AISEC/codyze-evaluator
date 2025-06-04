/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

/**
 * Represents a policy that defines authorization rules.
 *
 * @param underlyingNode The underlying CPG node.
 */
open class Policy(underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null) :
    de.fraunhofer.aisec.cpg.graph.concepts.Concept(underlyingNode = underlyingNode) {
    var rule: PolicyRule? = null
    var policyRef: de.fraunhofer.aisec.cpg.graph.Node? = null
}

/**
 * Represents a rule within a policy.
 *
 * @param underlyingNode The underlying CPG node.
 * @param roles The roles for this rule.
 */
open class PolicyRule(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val roles: Set<Role> = kotlin.collections.emptySet(),
) : de.fraunhofer.aisec.cpg.graph.concepts.Concept(underlyingNode = underlyingNode)

/**
 * Defines a role with a name and optional conditions.
 *
 * @param name The role name.
 * @param conditions The conditions for the role.
 */
data class Role(val name: String, val conditions: Set<String> = kotlin.collections.emptySet())
