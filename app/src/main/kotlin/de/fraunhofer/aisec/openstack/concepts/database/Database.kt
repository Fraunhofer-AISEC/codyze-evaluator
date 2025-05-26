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
 */
class DatabaseAccess(underlyingNode: Node? = null) : Concept(underlyingNode)

/**
 * Represents a filter operation on a database access.
 *
 * @param underlyingNode The underlying CPG node.
 * @param concept The database access.
 * @param by The node representing the filter condition.
 */
class Filter(underlyingNode: Node?, concept: DatabaseAccess, val by: Node) :
    Operation(underlyingNode, concept)
