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
