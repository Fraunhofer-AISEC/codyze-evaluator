/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.auth

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.newConcept

class Authorization(underlyingNode: Node? = null, policy: Policy) :
    Concept(underlyingNode = underlyingNode)

fun MetadataProvider.newAuthorization(underlyingNode: Node, policy: Policy, connect: Boolean) =
    newConcept(
        { Authorization(policy = policy) },
        underlyingNode = underlyingNode,
        connect = connect,
    )
