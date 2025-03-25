import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.concepts.iam.*

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
                children = endpoint.authentication?.let { mutableListOf(QueryTree<IdentityAccessManagement>(value = it)) }
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
            // There's some authorization decision before the secret is accessed
            val authentication = endpoint.authentication
            val authenticated = authentication != null
            if (!authenticated) {
                QueryTree<Boolean>(
                    value = false,
                    children = mutableListOf(),
                    stringRepresentation = "The endpoint $endpoint does not even require authentication",
                    node = endpoint,
                )
            } else {
                endpoint.underlyingNode?.let { underlyingNode ->
                    executionPath(
                        startNode = underlyingNode,
                        type = Must,
                        direction = Forward(GraphToFollow.EOG),
                        scope = Interprocedural(),
                        earlyTermination = { it is GetSecret },
                        predicate = { it is AuthorizeJwt },
                    )
                } ?: QueryTree<Boolean>(
                    value = false,
                    children = mutableListOf(),
                    stringRepresentation = "The endpoint $endpoint does not have an underlying node which could serve us as a starting point for the EOG",
                    node = endpoint,
                )
            }
        })
}

/**
 * Given a list of user permissions P (defined in permission
 * configs) and an authorization check A, a check is performed
 * on P and used as input to A.
 */
fun statement3(tr: TranslationResult): QueryTree<Boolean> {
    return QueryTree(true)
}
