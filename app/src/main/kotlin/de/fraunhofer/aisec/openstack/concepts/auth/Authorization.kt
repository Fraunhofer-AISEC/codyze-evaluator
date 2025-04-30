/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

/**
 * Represents an authorization context linked to a policy.
 *
 * @param underlyingNode The underlying CPG node.
 * @param policy The associated policy.
 */
class Authorization(underlyingNode: Node? = null, policy: Policy) :
    Concept(underlyingNode = underlyingNode)
