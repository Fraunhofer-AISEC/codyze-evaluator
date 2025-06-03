/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.concepts.database

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

/**
 * Represents a database access operation.
 *
 * @param underlyingNode The underlying CPG node.
 * @param context The context holding the user's domain information
 */
class DatabaseAccess(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node? = null,
    val context: de.fraunhofer.aisec.cpg.graph.Node?,
) : de.fraunhofer.aisec.cpg.graph.concepts.Concept(underlyingNode)

/**
 * Represents a filter operation on a database access.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The database access.
 * @param by The node representing the filter condition.
 */
class Filter(
    underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?,
    concept: DatabaseAccess,
    val by: de.fraunhofer.aisec.cpg.graph.Node,
) : de.fraunhofer.aisec.cpg.graph.concepts.Operation(underlyingNode, concept) {
    init {
        concept.ops.add(this)
    }
}
