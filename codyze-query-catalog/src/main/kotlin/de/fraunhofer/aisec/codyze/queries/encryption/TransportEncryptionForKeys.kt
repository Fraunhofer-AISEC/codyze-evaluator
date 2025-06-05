/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.eq

/**
 * The key must be protected when in transit.
 *
 * This query enforces the following statement: "Given a client call C that retrieves a key K from
 * the Barbican API, the transmission of K must utilize a secure, state-of-the-art, transport
 * protocol (e.g., specified in BSI TR-02102-1)."
 */
context(TranslationResult)
fun transportEncryptionForKeys(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    val tree =
        tr.allExtended<HttpRequest> { request ->
            // The HttpRequest must use TLS (i.e., the property isTLS of
            // the concept belonging to the request must be true).
            // We use the Query-API's infix function `eq` for the check.
            // Since this function requires a QueryTree object as input,
            // we use manually create one using the QueryTree of the isTLS
            // property.
            request.concept.isTLS eq true
        }

    return tree
}
