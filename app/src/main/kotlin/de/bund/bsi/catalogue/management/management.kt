/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept

open class managementPort(un: Node?) : Concept(un)

// Make sure that changes to the configuration / TSF are only possible by an (authenticated /
// authorized) admin
// No additional dataflows from the TOE to the developer except when configured by the admin
