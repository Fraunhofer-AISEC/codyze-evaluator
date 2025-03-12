import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest


fun statement1(result: TranslationResult): QueryTree<Boolean> {
    val tree = result.allExtended<HttpRequest> {
        QueryTree(it.concept.isTLS) eq true
    }

    return tree
}
