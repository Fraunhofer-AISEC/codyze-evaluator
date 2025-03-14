import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption
import de.fraunhofer.aisec.cpg.query.QueryTree
import de.fraunhofer.aisec.cpg.query.const
import de.fraunhofer.aisec.cpg.query.ge

val SYM_KEYLENGTH: Int = 256

/**
 * This query enforces the following statement: "Given a block device encryption E, if an encryption algorithm A is employed, then A must be a state-of-the-art cryptographic algorithm (e.g., BSI TR-02102-1)"
 *
 * TODO: update the allowedCiphers list to reflect the BSI TR
 */
fun statement1(tr: TranslationResult): QueryTree<Boolean> {
    val allowedCiphers = listOf("aes-xts-plain64", "aes-cbc-essiv")
    return tr.allExtended<DiskEncryption>() { QueryTree(it.cipher?.cipherName) IN allowedCiphers }
}

fun statement2(tr: TranslationResult): QueryTree<Boolean> {
    val tree = tr.allExtended<DiskEncryption> {
        const(it.key?.keySize ?: 0) ge const(SYM_KEYLENGTH)
    }

    return tree
}
