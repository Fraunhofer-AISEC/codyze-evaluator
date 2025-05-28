import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.bund.bsi.catalgoue.*
import de.bund.bsi.catalgoue.architecture.PlaintextBackupEndpoint
import de.bund.bsi.catalgoue.cryptography.Blockcipherkey
import de.bund.bsi.catalgoue.cryptography.EntropyPreservingFunction
import de.bund.bsi.catalgoue.cryptography.HMAC
import de.bund.bsi.catalgoue.cryptography.KeyGenerator
import de.bund.bsi.catalgoue.cryptography.MessageAuthenticationCode
import de.bund.bsi.catalgoue.cryptography.SymmetricEncrypt
import de.bund.bsi.catalgoue.network.HttpResponse
import de.bund.bsi.catalgoue.properties.Asset_Confidentiality
import de.bund.bsi.catalgoue.utils.nodeHasConcept
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with
import kotlin.reflect.typeOf


/** Secrets used as keys and all things derived from it must not be persisted (except from ciphertexts). */
fun secretKeysDoNotLeaveTheSystem (tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret>(
        sel = { secret -> true},
        mustSatisfy = { secret ->
            // The secret-dependent value must not leave the system except if it is the ciphertext where the secret was used as key.
            not(
                dataFlow(
                    startNode = secret,
                    type = May,
                    direction = Bidirectional(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    // Check if node is valid ciphertext. We do no longer follow such a path.
                    earlyTermination = { node -> onlyUsedAsKey(tr, node, secret) },
                    // HttpEndpoint is probably not the best match -> introduce Http Response as concept.
                    predicate = { it is WriteFile || it is LogWrite || (it is HttpEndpoint && it !is PlaintextBackupEndpoint)  }
                )
            )
        }
    )
}

/**
 * Returns `true` if the parameter `secret` is only used as a key in the encryption function.
 */
fun onlyUsedAsKey(tr: TranslationResult, node: Node, secret: Secret): Boolean {
    return tr.existsExtended<SymmetricEncrypt>(
        sel = { se ->
            not(
                dataFlow(secret,
                    type = May,
                    direction = Bidirectional(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    predicate = { node -> node == se},
                )
            ).value
        },
        mustSatisfy = { encrypt ->
            QueryTree<Boolean>(value = encrypt.ciphertext === node)
        }).value
}

// A blockcipherkey must be the result of a KeyGenerator, and may only be written over by an entropy preserving function
fun blockcipherkeysAreGeneratedByAKeyGeneratorAndPreserveEntropy(tr: TranslationResult) : QueryTree<Boolean>{

    return tr.allExtended<Blockcipherkey>(
        sel = {true},
        mustSatisfy = {bck ->
            dataFlow(
                startNode = bck,
                type = May,
                direction = Backward(GraphToFollow.DFG),
                scope = Interprocedural(),
                earlyTermination = {bck -> !nodeHasConcept<EntropyPreservingFunction>(bck)},
                predicate = {bck -> nodeHasConcept<KeyGenerator>(bck) })
                    }
            )
}


tag {

    // All Blockcipherkeys are confidential
    each<Node>( predicate = { nodeHasConcept<Blockcipherkey>(it) })
        .with { Asset_Confidentiality(null) }

    // HMAC is also a MAC.
    each<Node>( predicate = {nodeHasConcept<HMAC>(it)})
        .with { MessageAuthenticationCode(null) }
}