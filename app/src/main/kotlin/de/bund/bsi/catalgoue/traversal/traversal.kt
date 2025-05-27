/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalgoue.traversal

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

open class Port(un: Node?) : Concept(un)

open class DomainSeparationMechanism(un: Node?) : Concept(un)

/**
 * A DataStore can be a List<V>, Set<Pair<T,V>>, HashMap<T,V>, etc. where a key (some generic type, or index) is used to identify objects
 * stored in it. These objects can then again be used to implement the separation of domains within the TOE.
 * It must be described, how the keys are partitioned between different
 */
open class DataStore(un: Node?) : DomainSeparationMechanism(un)
open class DataStore_get(un: Node?) : Operation(un, DataStore(un))
open class DataStore_put(un: Node?) : Operation(un, DataStore(un))
