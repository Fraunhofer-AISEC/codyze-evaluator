/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalogue.traversal

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

open class Port(un: Node?) : Concept(un)

/**
 * A [de.bund.bsi.catalogue.traversal.DomainSeparationMechanism] is a class or function responsible for the separation of
 * users, resources, etc. It is most likely some form of list in which names (usernames, projectID, etc.) are mapped to resources and data (they
 * make up the "domain") or some intermediate form of such resources or data (like names or addresses to / of such things), and a function
 * looking up if an (already authenticated) user is allowed to access a specific resource or might get a list of a number of resources he owns.
 *
 * If users / processes of different domains communicate with the TOE over a shared endpoint, such a distinction is always needed.
 * Depending on the TOEs design, there might be different lists for each type of ressource, or a list for each domain that contains all resources
 * of given domain. In the former case, one must check if the separation of domains is correctly implemented and enforced on every access to the list.
 */
open class DomainSeparationMechanism(un: Node?) : Concept(un)

/**
 * A DataStore can be a List<V>, Set<Pair<T,V>>, HashMap<T,V>, etc. where a key (some generic type, or index) is used to identify objects
 * stored in it. These objects can then again be used to implement the separation of domains within the TOE.
 * It must be described, how the keys are partitioned between different domains.
 */
open class DataStore(un: Node?) : DomainSeparationMechanism(un)
open class DataStore_get(un: Node?) : Operation(un, DataStore(un))
open class DataStore_put(un: Node?) : Operation(un, DataStore(un))


/**
 * A function f mapping from U = A \cup B \cup C... to V = a \cup b \cup c..., such that for a set of sets \{A, B, C, D, ...\}
 * and a set of set \{a, b, c, d, ...\} it is true that
 * \forall e \in A: f(e) \in a
 * \forall e \in B: f(e) \in b
 * ...
 * A partition can be combined with a different partition mapping from \{a, b, c, ... \} to \{I, II, III, IV, ...\} to form a third partition, since they are
 * simply renaming, adding or removing the elements in the respective sets without shuffling the elements between the sets.
 * See domain separation in "properties" for example usage.
 */
open class PartitionFunction(un: Node?) : Concept(un)
