/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DeAllocate
import de.fraunhofer.aisec.cpg.query.*

/**
 * This query enforces the following statement: Given a customer-managed (retrieved by a [GetSecret]
 * operation), it must not leave the component via any data flow that can is considered a leak.
 *
 * Which data flow is considered a leak is defined by the function [isLeakyOutput].
 */
context(TranslationResult)
fun keyNotLeakedThroughOutput(isLeakyOutput: Node.() -> Boolean): QueryTree<Boolean> {
    val tr = this@TranslationResult

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
                    // Use the function `dataLeavesComponent` above to represent a sink.
                    predicate = { it.isLeakyOutput() },
                ) // If this returns a QueryTree<Boolean> with value `true`, a dataflow may be
                // present.
            ) // We want to negate this result because such a flow must not happen.
        }

    return noKeyLeakResult
}

/**
 * This query enforces the following statement: "Given a customer-managed key K used for disk
 * encryption, K must only be retrieved from a secure key provider." If a [Node] of type [T] is a
 * secure key provider as required by the query is decided by [isSecureKeyProvider].
 */
context(TranslationResult)
inline fun <reified T : Node> encryptionKeyOriginatesFromSecureKeyProvider(
    crossinline isSecureKeyProvider: T.() -> Boolean
): QueryTree<Boolean> {
    val tr = this@TranslationResult

    val tree =
        tr.allExtended<DiskEncryption> { encryption ->
            // We start with a disk encryption operation and check if the key is present.
            encryption.key?.let { key ->
                // This key must originate from a secure key provider. In our case, this is the
                // Barbican API endpoint.
                // We perform this check with a backward data flow analysis.
                dataFlow(
                    // We start our data flow analysis at the encryption key.
                    startNode = key,
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
                    // The requirement is satisfied if the key comes from a secure key provider.
                    // We use the extension function `isSecureKeyProvider` defined above to perform
                    // this check.
                    predicate = { it is T && it.isSecureKeyProvider() },
                )
            }
                // If there's no key present for the encryption, there's something wrong.
                // In this case, we create a QueryTree with value `false` manually.
                ?: QueryTree(
                    value = false,
                    children =
                        mutableListOf(
                            QueryTree(encryption, operator = GenericQueryOperators.EVALUATE)
                        ),
                    stringRepresentation = "encryptionOp.concept.key is null",
                    node = encryption,
                    operator = GenericQueryOperators.EVALUATE,
                )
        }

    return tree
}

/**
 * This query enforces the following statement: "Given a device encryption operation O, the key K
 * used in O must be deleted from memory after the operation is completed."
 */
context(TranslationResult)
fun keyIsDeletedFromMemoryAfterUse(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    val tree =
        tr.allExtended<DiskEncryption> { diskEncryption ->
            // We start with the disk encryption operation and check if the key is present.
            // For this key, we get all `GetSecret` operations, i.e., all operations which
            // may be used to generate the secret key.
            diskEncryption.key
                ?.ops
                ?.filterIsInstance<GetSecret>()
                ?.map { secret ->
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
                ?.mergeWithAll() // Since there might be multiple `GetSecret` operations, we need to
                // check if all of them are de-allocated.
                ?: QueryTree(
                    value = false,
                    stringRepresentation = "All keys must be deleted but there is nothing",
                    node = diskEncryption,
                    operator = GenericQueryOperators.EVALUATE,
                )
        }
    return tree
}
