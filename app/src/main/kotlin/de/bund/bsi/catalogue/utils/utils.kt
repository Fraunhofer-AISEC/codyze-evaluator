/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalogue.utils

import de.bund.bsi.catalogue.properties.InformationAnnihilator
import de.fraunhofer.aisec.cpg.graph.Node

fun goesIntoInformationAnnihilator(searchNode: Node): Boolean {
    return searchNode.nextEOG.all { nextEOGNodes -> nextEOGNodes is InformationAnnihilator }
}

/** Returns true, iff a given [node] was assigned the given concept [T]. */
inline fun <reified T> nodeHasConcept(node: Node): Boolean {

    return node.overlays.any { overlayNode -> overlayNode is T }
}

/**
 * Checks, if for every possible way for the program to reach this code / node, a specific condition
 * holds, i.e. the control flow must have gone through a function checking a specific predicate.
 * Such a function is assigned the concept [T].
 */
inline fun <reified T> programStateDependsOn(node: Node): Boolean {
    return TODO()
}

/**
 * Checks, if there is a dataflow from a node tagged with concept [T] into this node regardless of
 * any other additional data flow. However, this query checks, if there is an
 * [InformationAnnihilator] between [T] and this node (then it returns false).
 */
inline fun <reified T> dataDependsOn(node: Node): Boolean {
    return TODO()
}
