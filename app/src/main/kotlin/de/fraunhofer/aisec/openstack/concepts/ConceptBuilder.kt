/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.NodeBuilder
import de.fraunhofer.aisec.cpg.graph.codeAndLocationFrom
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

/** This function creates a new [Concept] node based on [ConceptClass]. */
internal inline fun <reified ConceptClass : Concept> MetadataProvider.newConcept(
    constructor: (underlyingNode: Node) -> (ConceptClass),
    underlyingNode: Node,
): ConceptClass {
    val node = constructor(underlyingNode)
    node.codeAndLocationFrom(underlyingNode)

    node.name = Name("${ConceptClass::class.simpleName}[" + underlyingNode.name.toString() + "]")

    NodeBuilder.log(node)
    return node
}

/** This function creates a new [Operation] node based on [OperationClass]. */
fun <OperationClass : Operation, ConceptClass : Concept> MetadataProvider.newOperation(
    constructor: (underlyingNode: Node, concept: ConceptClass) -> (OperationClass),
    underlyingNode: Node,
    concept: ConceptClass,
): OperationClass {
    val node = constructor(underlyingNode, concept)
    node.codeAndLocationFrom(underlyingNode)

    node.name = concept.name

    concept.ops += node
    node.nextDFG += underlyingNode.nextDFG
    node.prevDFG += underlyingNode.prevDFG
    node.prevEOG += underlyingNode
    node.nextEOG += underlyingNode

    NodeBuilder.log(node)
    return node
}
