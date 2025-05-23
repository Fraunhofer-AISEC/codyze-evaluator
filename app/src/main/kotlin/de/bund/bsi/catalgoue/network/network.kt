/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalgoue.network

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint

class HttpResponse(underlyingNode: Node?, val httpEndpoint: HttpEndpoint) : Concept(underlyingNode)
