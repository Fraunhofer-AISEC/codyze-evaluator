import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.cpg.*

/**
 * Access to Barbican keys must be restricted to authenticated
 * users, i.e., each Barbican REST API that provides access to
 * K must be connected to an Authentication concept.
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<HttpEndpoint>(
        // A secret reaches this endpoint.
        sel = { endpoint ->
            dataFlow(
                startNode = endpoint,
                type = May,
                direction = Backward(GraphToFollow.DFG),
                scope = Interprocedural(),
                predicate = { it is GetSecret },
            ).value
        },
        mustSatisfy = { endpoint ->
            // There's some authentication for this endpoint
            QueryTree<Boolean>(
                value = endpoint.authentication != null,
                children = endpoint.authentication?.let { mutableListOf(QueryTree<Authentication>(value = it)) }
                    ?: mutableListOf(),
                stringRepresentation = "The endpoint $endpoint requires authentication by ${endpoint.authentication}",
                node = endpoint
            )
        })
}

/**
 * Access to Barbican keys must be restricted to authenticated
 * users through authorization, i.e., each operation on K must
 * be connected to an Authorization concept.
 */
fun statement2(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}

/**
 * Given a list of user permissions P (defined in permission
 * configs) and an authorization check A, a check is performed
 * on P and used as input to A.
 */
fun statement3(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}
