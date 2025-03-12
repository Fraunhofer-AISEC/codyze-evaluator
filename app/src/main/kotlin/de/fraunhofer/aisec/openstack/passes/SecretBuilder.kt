/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*

// TODO: move to a better location
fun MetadataProvider.newSecret(underlyingNode: Node): Secret {
    val node = Secret(underlyingNode = underlyingNode)
    node.codeAndLocationFrom(underlyingNode)

    node.name = Name("Key[" + underlyingNode.name.toString() + "]")
    underlyingNode.nextDFG += node
    NodeBuilder.log(node)
    return node
}

/**
 * Creates a new [GetSecret] node. This new node:
 * - copies the [Name] from the related [concept] node
 * - Adds a DFG edge to the related [underlyingNode]
 */
fun MetadataProvider.newGetSecret(underlyingNode: Node, concept: Secret): GetSecret {
    val node = GetSecret(underlyingNode = underlyingNode, concept = concept)
    node.codeAndLocationFrom(underlyingNode)

    node.name = concept.name

    concept.ops += node
    node.nextDFG += underlyingNode.nextDFG

    NodeBuilder.log(node)
    return node
}
