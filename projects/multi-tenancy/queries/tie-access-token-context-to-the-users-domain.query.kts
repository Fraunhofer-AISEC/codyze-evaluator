import de.fraunhofer.aisec.cpg.graph.concepts.auth.TokenBasedAuth
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authenticate

/**
 * Checks if any [Authenticate] uses a [TokenBasedAuth] where the
 * token is equal to the credential of that [Authenticate].
 */
fun Authenticate.usesSameTokenAsCredential(): QueryTree<Boolean> {
    return this.allExtended<Authenticate>(
        mustSatisfy = { token ->
            val tokens = token.credential.overlays.filterIsInstance<TokenBasedAuth>()
            val hasTokenDataFlow = tokens.any { it.token == token.credential }
            QueryTree(value = hasTokenDataFlow, node = token)
        }
    )
}

/**
 * Checks if there is a data flow from the credential of this [Authenticate] into an
 * [ExtendedRequestContext], where user-related info is set.
 */
fun Authenticate.hasDataFlowIntoContext(): QueryTree<Boolean> {
    return dataFlow(
        startNode = this.credential,
        predicate = { target ->
            target.overlays.filterIsInstance<ExtendedRequestContext>().any {
                it.userInfo?.userId != null &&
                        it.userInfo?.projectId != null &&
                        it.userInfo?.domainId != null
            }
        },
    )
}

/**
 * Checks that when an access token is validated, its context is tied to the user’s domain/project.
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Authenticate>(
        mustSatisfy = { it.usesSameTokenAsCredential() and it.hasDataFlowIntoContext() }
    )
}