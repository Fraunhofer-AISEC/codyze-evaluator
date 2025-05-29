/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalogue.architecture

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.auth.RequestContext
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration

/** The module that orchestrates self tests */
open class SelfTestModule()

/** A module that participates in the self tests orchestrated by the SelfTestModule */
open class TestedModule()

/**
 * A port of a toe internal domain that potentially allows toe internal data (or user data) to leave
 * the domain Depending on the TOE design, this port might require additional protection. For
 * example, if data is transported over an untrusted network, such a port must apply cryptographic
 * mechanisms on the user data.
 */
open class ToeInternalPort(un: Node?) : Concept(un)

open class PlaintextBackupEndpoint(
    underlyingNode: FunctionDeclaration? = null,
    httpMethod: HttpMethod,
    path: String,
    arguments: List<Node>,
    authentication: Authentication?,
    authorization: Authorization?,
    requestContext: RequestContext?,
) :
    HttpEndpoint(
        underlyingNode,
        httpMethod,
        path,
        arguments,
        authentication,
        authorization,
        requestContext,
    )


// Avoid injection attacks

/**
 * User input probably needs to be transformed (e.g. using prepared statements for a sql-statements,
 * or HTML-encoding if something based on the input is part of a website).
 */
open class UserInputTransformator(un: Node?) : Concept(un)

