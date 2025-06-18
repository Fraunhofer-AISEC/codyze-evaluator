/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.queries.encryption

import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.assumptions.AssumptionType
import de.fraunhofer.aisec.cpg.assumptions.addAssumptionDependence
import de.fraunhofer.aisec.cpg.assumptions.assume
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.query.GenericQueryOperators
import de.fraunhofer.aisec.cpg.query.IN
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.allExtended
import de.fraunhofer.aisec.cpg.query.ge
import de.fraunhofer.aisec.cpg.query.mergeWithAll

/**
 * The minimum key length for symmetric encryption algorithms. According to BSI TR-02102-1, this
 * should be at least 256 bits.
 */
const val SYM_KEYLENGTH = 256

/** The list of allowed ciphers for block device encryption. */
val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")

/**
 * The block device encryption algorithm must be state of the art, e.g., refer to a TR.
 *
 * This query enforces the following statement: "Given a block device encryption E, if an encryption
 * algorithm A is employed, then A must be a state-of-the-art cryptographic algorithm (e.g., BSI
 * TR-02102-1)"
 *
 * Note that BSI TR-02102-1 only mentions aes-xts as having "relatively good security properties and
 * efficiency"
 */
context(TranslationResult)
fun stateOfTheArtEncryptionIsUsed(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    // We currently allow the two ciphers aes-xts-plain64 and aes-cbc-essiv.
    // This could be extracted to a variable outside this statement.
    val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")

    // The predicate must hold for all DiskEncryption concepts.
    return tr.allExtended<DiskEncryption> {
        // Note, this is intentionally using a more complex structure because otherwise we had a
        // problem that this query tree and the one with key size had the same ID.
        if (it.cipher == null) {
            // If the cipher is null, we assume that the user may not have configured it correctly.
            // We return a QueryTree with a false value and an assumption.
            QueryTree(
                    value = false,
                    node = it,
                    operator = GenericQueryOperators.EVALUATE,
                    stringRepresentation = "Key cipher is null",
                )
                .assume(
                    AssumptionType.InputAssumptions,
                    "We assume that the cipher may not have been configured in a good way by the user because the query returned an empty result.\n\n",
                )
        } else {
            listOfNotNull(it.cipher)
                .map { cipher ->
                    if (cipher.cipherName != null) {
                        // If the cipher's name is not null, we check if cipher is in the list of
                        // allowed ciphers.
                        // We use the Query-API's infix function `IN` for the check.
                        // Since this function requires a QueryTree object as input,
                        // we use manually create one based on the cipher's name.
                        QueryTree(
                            value = cipher.cipherName,
                            node = cipher,
                            operator = GenericQueryOperators.EVALUATE,
                        ) IN allowedCiphers
                    } else {
                        QueryTree(
                                value = false,
                                node = cipher,
                                operator = GenericQueryOperators.EVALUATE,
                                stringRepresentation = "Key cipher is null",
                            )
                            .assume(
                                AssumptionType.InputAssumptions,
                                "We assume that the cipher may not have been configured in a good way by the user because the query returned an empty result.\n\n",
                            )
                    }
                }
                .mergeWithAll()
        }
    }
}

/**
 * The block device encryption algorithm must be state of the art, e.g., refer to a TR.
 *
 * This query enforces the following statement: "Given a block device encryption E, if an encryption
 * algorithm A is employed, A must support a minimum key length L with L >= 256."
 */
context(TranslationResult)
fun minimalKeyLengthIsEnforced(): QueryTree<Boolean> {
    val tr = this@TranslationResult

    // The inner predicate has to hold for each DiskEncryption concept
    val tree =
        tr.allExtended<DiskEncryption> {
            // Get the key of the DiskEncryption concept and its size.
            // If the key is `null`, we do not really know and set the size to 0.
            // Then, compare it with the SYM_KEYLENGTH (which is 256).
            // It has to be greater or equal (infix function `ge` of the Query-API).
            // Since this function requires a QueryTree object as input,
            // we use create with the Query-API's `const` function.
            it.key?.keySize?.let { keySize ->
                QueryTree(
                        value = keySize,
                        node = it.key ?: it,
                        operator = GenericQueryOperators.EVALUATE,
                    )
                    .addAssumptionDependence(it.key) ge SYM_KEYLENGTH
            }
                ?: QueryTree(
                        value = false,
                        node = it.key ?: it,
                        operator = GenericQueryOperators.EVALUATE,
                        stringRepresentation = "Key size is null",
                    )
                    .assume(
                        AssumptionType.InputAssumptions,
                        "We assume that the key size may not have been configured in a good way by the user because the query returned an empty result.\n\n",
                    )
        }

    return tree
}
