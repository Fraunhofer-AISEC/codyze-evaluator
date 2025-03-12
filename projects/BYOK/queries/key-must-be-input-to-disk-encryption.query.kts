import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.edges.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*

fun statement1(result: TranslationResult): QueryTree<Boolean> {
    /**
     * The following http endpoints are considered as a secure key provider:
     * * GET /v1/secrets/{encryption_key_id}/payload in the `Component` "Barbican"
     */
    fun HttpEndpoint.isSecureKeyProvider(): Boolean {
        return httpMethod == HttpMethod.GET &&
                path == "/v1/secrets/{secret_id}/payload" &&
                this.underlyingNode?.firstParentOrNull {
                    it is Component && it.name.localName == "barbican"
                } != null
    }

    val tree = result.allExtended<DiskEncryption> { encryption ->
        encryption.key?.let { key ->
            result
                .existsExtended<HttpEndpoint>(HttpEndpoint::isSecureKeyProvider) {
                    dataFlow(
                        it,
                        encryption,
                        useIndexStack = true,
                        collectFailedPaths = false,
                    )
                }
                .children
                .firstOrNull() as? QueryTree<Boolean> ?: QueryTree(false)
        }
            ?: QueryTree(
                false,
                mutableListOf(QueryTree(encryption)),
                "encryptionOp.concept.key is null",
            )
    }

    return tree
}

fun statement2(result: TranslationResult): QueryTree<Boolean> {
    val tree = result.allExtended<DiskEncryption> {
        val processInput =
            (it.underlyingNode as? CallExpression)?.argumentEdges?.get("process_input")?.end
        if (processInput == null) {
            QueryTree(true)
        } else {
            executionPath(it) { to ->
                to is DeAllocate &&
                        (to.what as? Reference)?.refersTo ==
                        (processInput as? Reference)?.refersTo
            }
        }
    }

    return tree
}
