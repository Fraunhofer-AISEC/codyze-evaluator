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
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [HttpEndpoint] is invoked on is considered a secure key provider.
 *
 * The following http endpoints are considered as a secure key provider:
 * * GET /v1/secrets/{encryption_key_id}/payload in the `Component` "Barbican"
 *
 * @return `true` if the [HttpEndpoint] is a secure key provider, `false` otherwise
 */
fun HttpEndpoint.isSecureKeyProvider(): Boolean {
    return httpMethod == HttpMethod.GET &&
            path == "/v1/secrets/{secret_id}/payload" &&
            this.underlyingNode?.firstParentOrNull<Component> {
                it.name.localName == "barbican"
            } != null
}

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [Node] is invoked on may be used to leak sensitive data outside of the component by
 * considering the following channels:
 * - Writing to a file
 * - Writing to a log
 * - Printing to the console (via a call expression `println`)
 * - Executing a command (via a call expression `execute`)
 * - Being exposed via an Http endpoint which is not explicitly whitelisted by being a "secure key provider"
 *
 * @return `true` if this [Node] can be used to leak data.
 */
fun Node.dataLeavesComponent(): Boolean {
    return this is WriteFile ||
            this is LogWrite ||
            (this is HttpEndpoint && !this.isSecureKeyProvider()) ||
            (this is CallExpression && (this.name.localName == "println" || this.name.localName == "execute"))
}

/**
 * Given a customer-managed key K stored in Barbican, it must not be
 * leaked via printing, logging, file writing or command execution input.
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    // The result of a `GetSecret` operation must not have a data flow
    // to a node which can be used to leak sensitive data according to
    // the function `dataLeavesComponent`.
    val noKeyLeakResult =
        // We start by collecting all nodes getting a secret and check if
        // the requirement holds for all of them.
        tr.allExtended<GetSecret> { secret ->
            not(
                dataFlow(
                    // The source is the GetSecret operation.
                    startNode = secret,
                    // May analysis because a single data flow is enough to violate the requirement
                    type = May,
                    // Consider all paths across functions.
                    scope = Interprocedural(),
                    // Use the function `dataLeavesComponent` defined above to represent a sink.
                    predicate = { it.dataLeavesComponent() },
                ) // If this returns a QueryTree<Boolean> with value `true`, a dataflow may be present.
            ) // We want to negate this result because such a flow must not happen.
        }

    return noKeyLeakResult
}

/**
 * Given a customer-managed key K stored in Barbican, K must only be accessible via the Barbican API endpoint.
 */
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
                ) // If there's no key present for the encryption, there's something wrong, so we create a QueryTree with value false manually.
        }

    return tree
}

/**
 * Given a device encryption operation O, the key K used in O must be deleted from memory after the operation is completed.
 */
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
