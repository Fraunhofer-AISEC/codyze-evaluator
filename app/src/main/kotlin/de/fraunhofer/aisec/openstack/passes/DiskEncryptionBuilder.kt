/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*

// TODO: move to a better location
fun MetadataProvider.newDiskEncryption(
    underlyingNode: Node,
    cipher: Cipher?,
    key: Secret?,
): DiskEncryption {
    val node = DiskEncryption(underlyingNode = underlyingNode)
    node.codeAndLocationFrom(underlyingNode)

    node.name = Name("DiskEnc[" + underlyingNode.name.toString() + "]")
    cipher?.let { node.cipher = it }
    key?.let {
        node.key = it
        // node.prevDFG += it
    }

    // needed for the query
    node.prevDFG += underlyingNode
    node.prevEOG += underlyingNode
    node.nextEOG += underlyingNode

    NodeBuilder.log(node)
    return node
}

fun MetadataProvider.newCipher(underlyingNode: Node): Cipher {
    val node = Cipher(underlyingNode = underlyingNode)
    node.codeAndLocationFrom(underlyingNode)

    node.name = Name("Cipher[" + underlyingNode.name.toString() + "]")

    NodeBuilder.log(node)
    return node
}
