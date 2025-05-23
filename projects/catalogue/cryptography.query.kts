import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.bund.bsi.catalgoue.*
import de.bund.bsi.catalgoue.cryptography.Blockcipherkey
import de.bund.bsi.catalgoue.cryptography.SymmetricEncrypt
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with

/** Secrets used as keys and all things derived from it must not be persisted (except from ciphertexts). */
fun secretKeysDoNotLeaveTheSystem (tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret>(
        sel = { secret -> true
            // The secret is a key if it's used in an encryption function.
            /* dataFlow(
                startNode = secret,
                type = May,
                direction = Bidirectional(GraphToFollow.DFG),
                scope = Interprocedural(),
                predicate = { it is Encrypt },
            ).value */
        },
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
                    predicate = { it is WriteFile || it is LogWrite || (it is HttpResponse && (it.httpEndpoint !is PlaintextBackupEndpoint))  },
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


tag {
    each<Node>( predicate = {it.overlays.any { it is Blockcipherkey } })
        .with { Secret() }

    each<FunctionDeclaration>(predicate = TODO())
        .with { PlaintextBackupEndpoint() }
}