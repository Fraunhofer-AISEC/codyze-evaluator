/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.query.*
import de.fraunhofer.aisec.openstack.queries.OpenStackComponents

/**
 * A list of whitelisted [HttpEndpoint]s that are considered secure key providers.
 *
 * These endpoints are allowed receive secret material without it being a leak.
 */
val secretsWhitelist =
    listOf(
        "barbican.api.controllers.secrets.SecretController.payload.HttpEndpoint",
        "barbican.api.controllers.secrets.SecretController.on_get.HttpEndpoint",
    )

/**
 * These functions are considered leaks of sensitive data outside the component, if secrets are
 * written with them.
 */
val leakingFunctions = listOf("write", "println", "execute", "log")

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
            it.name.localName == OpenStackComponents.BARBICAN
        } != null
}

/**
 * This [Kotlin extension function](https://kotlinlang.org/docs/extensions.html#extension-functions)
 * checks if the [Node] it is invoked on may be used to leak sensitive data outside of the component
 * by considering the following channels:
 * - Writing to a file
 * - Writing to a log
 * - Printing to the console (via a call expression `println`)
 * - Executing a command (via a call expression `execute`)
 * - Being exposed via an Http endpoint which is not explicitly whitelisted by being a "secure key
 *   provider"
 *
 * @return `true` if this [Node] can be used to leak data.
 */
fun Node.dataLeavesComponent(): Boolean {

    return this is WriteFile ||
        this is LogWrite ||
        ((this is CallExpression) && (this.name.localName in leakingFunctions)) ||
        (this is HttpEndpoint && this.name.toString() !in secretsWhitelist)
}

/**
 * This query enforces the following statement: "Given a customer-managed key K stored in Barbican,
 * it must not be leaked via printing, logging, file writing or command execution input."
 */
fun keyNotLeakedThroughOutput(tr: TranslationResult): QueryTree<Boolean> {
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
                ) // If this returns a QueryTree<Boolean> with value `true`, a dataflow may be
                // present.
            ) // We want to negate this result because such a flow must not happen.
        }

    return noKeyLeakResult
}

/**
 * This query enforces the following statement: "Given a customer-managed key K used for disk
 * encryption, K must only be accessible via the Barbican API endpoint."
 */
fun keyOnlyReachableThroughSecureKeyProvider(result: TranslationResult): QueryTree<Boolean> {
    val tree =
        result.allExtended<DiskEncryption> { encryption ->
            // We start with a disk encryption operation and check if the key is present.
            encryption.key?.let { key ->
                // This key must originate from a secure key provider. In our case, this is the
                // Barbican API endpoint.
                // We perform this check with a backward data flow analysis.
                dataFlow(
                    // We start our data flow analysis at the encryption operation.
                    startNode = encryption,
                    // We want to make sure that each DFG-path leads us to the Barbican API
                    // endpoint, so we use a Must analysis.
                    type = Must,
                    // We want to follow the data flow in the backward direction.
                    direction = Backward(GraphToFollow.DFG),
                    // These arguments tell that we want to perform a context- and field sensitive
                    // analysis.
                    // This is actually the default setting, so it's optional to specify this.
                    sensitivities = FieldSensitive + ContextSensitive,
                    // We want to consider all paths across functions, i.e., perform an
                    // interprocedural analysis.
                    scope = Interprocedural(),
                    // The requirement is satisified if the key comes from a secure key provider.
                    // We use the extension function `isSecureKeyProvider` defined above to perform
                    // this check.
                    predicate = { it is HttpEndpoint && it.isSecureKeyProvider() },
                )
            }
                // If there's no key present for the encryption, there's something wrong.
                // In this case, we create a QueryTree with value `false` manually.
                ?: QueryTree(
                    value = false,
                    children = mutableListOf(QueryTree(encryption)),
                    stringRepresentation = "encryptionOp.concept.key is null",
                    node = encryption,
                )
        }

    return tree
}

/**
 * This query enforces the following statement: "Given a device encryption operation O, the key K
 * used in O must be deleted from memory after the operation is completed."
 */
fun keyIsDeletedFromMemoryAfterUse(result: TranslationResult): QueryTree<Boolean> {
    val tree =
        result.allExtended<DiskEncryption> { diskEncryption ->
            // We start with the disk encryption operation and check if the key is present.
            // For this key, we get all `GetSecret` operations, i.e., all operations which
            // may be used to generate the secret key.
            val subQueries =
                diskEncryption.key?.ops?.filterIsInstance<GetSecret>()?.map { secret ->
                    // For each secret, we check if it is de-allocated.
                    // The function `alwaysFlowsTo` checks if there's a data flow to a node
                    // fulfilling
                    // the predicate on every possible execution path starting at the node `secret`.
                    secret.alwaysFlowsTo(
                        // We perform an interprocedural analysis.
                        scope = Interprocedural(),
                        // We do not want to track unreachable EOG paths and we perform a context-
                        // and field-sensitive analysis.
                        sensitivities = FilterUnreachableEOG + FieldSensitive + ContextSensitive,
                        // We require a de-allocate operation to be present which affects the
                        // secret.
                        predicate = { it is DeAllocate },
                    )
                }
            // Since there might be multiple `GetSecret` operations, we need to check if all of them
            // are de-allocated.
            // We do so by creating a single QueryTree object with value `true` if the query above
            // is fulfilled for all
            // `GetSecret` operations. If the key was `null`, the result will be `false`.
            QueryTree(
                value = subQueries?.all { it.value } ?: false,
                // Store the sub-queries into the list of children.
                children = subQueries?.map { QueryTree(it) }?.toMutableList() ?: mutableListOf(),
                stringRepresentation = "All keys must be deleted",
                node = diskEncryption,
            )
        }
    return tree
}
