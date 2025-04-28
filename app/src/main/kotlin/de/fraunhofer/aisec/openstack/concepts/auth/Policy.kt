/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

class Policy(underlyingNode: Node? = null) : Concept(underlyingNode = underlyingNode) {
    var rule: PolicyRule? = null
    //    val operations: MutableList<Node> = mutableListOf()
}

class PolicyRule(underlyingNode: Node? = null, val roles: Set<Role> = emptySet()) :
    Concept(underlyingNode = underlyingNode)

data class Role(val name: String, val conditions: Set<String> = emptySet())
