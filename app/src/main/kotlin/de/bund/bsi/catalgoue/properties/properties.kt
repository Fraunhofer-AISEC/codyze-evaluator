/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

// Some generic properties of variables and functions

open class ImmutableObject(un: Node?) : Concept(un)

open class InjectiveFunction(un: Node?) : Concept(un)

/**
 * Is a function that removes the information contained in all concepts in "annihilatedNodes"
 * from cleanedNodes, i.e. even if there is technically an information flow from one node in aN to a node in cN,
 * a node tagged with this concept removes it.
 * Examples:
 * c = a * 0        with c in cleanedNodes, a in annihilatedNodes
 * c = enc(k; a)    with c in cleanedNodes, a in annihilatedNodes, k a block cipher key, enc an encryption function
 *
 */
open class InformationAnnihilator(un: Node?, annihilatedNodes: List<Concept>, cleanedNodes: List<Concept>) : Concept(un)


open class Asset_Confidentiality(un: Node?) : Concept(un)

open class Asset_Integrity(un: Node?) : Concept(un)

open class Asset_Availability(un: Node?) : Concept(un)
