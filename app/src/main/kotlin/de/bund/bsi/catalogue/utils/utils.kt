/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalogue.utils

import de.bund.bsi.catalogue.properties.InformationAnnihilator
import de.fraunhofer.aisec.cpg.graph.Node

fun goesIntoInformationAnnihilator(searchNode: Node): Boolean {
    return searchNode.nextEOG.all { nextEOGNodes -> nextEOGNodes is InformationAnnihilator }
}

inline fun <reified T> nodeHasConcept(node: Node): Boolean {

    return node.overlays.any { overlayNode -> overlayNode is T }
}
