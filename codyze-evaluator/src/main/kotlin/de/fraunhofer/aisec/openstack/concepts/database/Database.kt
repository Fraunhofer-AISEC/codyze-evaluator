/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.concepts.database

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

/**
 * Represents a database access operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param context The context holding the user's domain information
 */
class DatabaseAccess(underlyingNode: Node? = null, val context: Node?) : Concept(underlyingNode)

/**
 * Represents a filter operation on a database access.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The database access.
 * @param by The node representing the filter condition.
 */
class Filter(underlyingNode: Node?, concept: DatabaseAccess, val by: Node) :
    Operation(underlyingNode, concept) {
    init {
        concept.ops.add(this)
    }
}
