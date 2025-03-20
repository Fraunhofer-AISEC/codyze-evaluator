import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.edges.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.file.*
import de.fraunhofer.aisec.cpg.graph.concepts.logging.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.concepts.memory.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*

/**
 * The following http endpoints are considered as a secure key provider:
 * * GET /v1/secrets/{encryption_key_id}/payload in the `Component` "Barbican"
 */
fun HttpEndpoint.isSecureKeyProvider(): Boolean {
    return httpMethod == HttpMethod.GET &&
            path == "/v1/secrets/{secret_id}/payload" &&
            this.underlyingNode?.firstParentOrNull<Component> {
                it.name.localName == "barbican"
            } != null
}

/**
 * Checks if the data may leave the component via one of the following channels:
 * - Writing to a file
 * - Writing to a log
 * - Printing to the console
 * - Executing a command
 * - Being exposed via an Http endpoint which is not explicitly whitelisted by being a "secure key provider"
 */
fun Node.dataLeavesComponent(): Boolean {
    return this is WriteFile ||
            this is LogWrite ||
            (this is HttpEndpoint && !this.isSecureKeyProvider()) ||
            (this is CallExpression && (this.name.localName == "println" || this.name.localName == "execute"))
}

fun statement1(tr: TranslationResult): QueryTree<Boolean> {

    val noKeyLeakResult =
        tr.allExtended<GetSecret> { secret ->
            not(
                dataFlow(
                    startNode = secret,
                    type = May,
                    scope = Interprocedural(),
                    predicate = { it.dataLeavesComponent() },
                )
            )
        }

    return noKeyLeakResult
}

fun statement2(result: TranslationResult): QueryTree<Boolean> {
    val tree =
        result.allExtended<DiskEncryption> { encryption ->
            encryption.key?.let { key ->
                dataFlow(
                    startNode = encryption,
                    type = May,
                    direction = Backward(GraphToFollow.DFG),
                    sensitivities = FieldSensitive + ContextSensitive,
                    scope = Interprocedural(),
                    predicate = { it is HttpEndpoint && it.isSecureKeyProvider() },
                )
            }
                ?: QueryTree(
                    false,
                    mutableListOf(QueryTree(encryption)),
                    "encryptionOp.concept.key is null",
                )
        }

    return tree
}

fun statement3(result: TranslationResult): QueryTree<Boolean> {
    val tree = result.allExtended<DiskEncryption> { diskEncryption ->
        val subQueries = diskEncryption.key?.ops?.filterIsInstance<GetSecret>()?.map { secret ->
            secret.alwaysFlowsTo(
                scope = Interprocedural(maxSteps = 100),
                sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
                predicate = { it is DeAllocate }, // Anforderung: de-allocate the data
            )
        }
        QueryTree(
            subQueries?.all { it.value == true } ?: false,
            subQueries?.map { QueryTree(it) }?.toMutableList() ?: mutableListOf(),
            "All keys must be deleted",
            diskEncryption
        )
    }
    return tree
}
