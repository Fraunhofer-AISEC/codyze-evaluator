/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts

import de.fraunhofer.aisec.cpg.graph.MetadataProvider
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.memory.Allocate
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.graph.concepts.memory.Memory
import de.fraunhofer.aisec.cpg.graph.concepts.memory.MemoryManagementMode

/** Creates a new [Memory] concept with the given [mode] and [underlyingNode]. */
fun MetadataProvider.newMemory(underlyingNode: Node, mode: MemoryManagementMode) =
    newConcept({ Memory(it, mode) }, underlyingNode)

/** Creates a new [Allocate] operation with the given [underlyingNode] and [what]. */
fun Memory.newAllocate(underlyingNode: Node, what: Node?) =
    newOperation({ node, concept -> Allocate(node, concept, what) }, underlyingNode, this)

/** Creates a new [DeAllocate] operation with the given [underlyingNode] and [what]. */
fun Memory.newDeAllocate(underlyingNode: Node, what: Node?) =
    newOperation({ node, concept -> DeAllocate(node, concept, what) }, underlyingNode, this)
