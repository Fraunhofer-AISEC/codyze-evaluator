import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest

/**
 * Given a client call C that retrieves a key K from the Barbican API,
 * the transmission of K must utilize a secure, state-of-the-art,
 * transport protocol (e.g., specified in BSI TR-02102-1).
 */
fun statement1(result: TranslationResult): QueryTree<Boolean> {
    val tree = result.allExtended<HttpRequest> { request ->
        // The HttpRequest must use TLS (i.e., the property isTLS of
        // the concept belonging to the request must be true).
        // We use the Query-API's infix function `eq` for the check.
        // Since this function requires a QueryTree object as input,
        // we use manually create one using the QueryTree of the isTLS
        // property.
        QueryTree(request.concept.isTLS) eq true
    }

    return tree
}
