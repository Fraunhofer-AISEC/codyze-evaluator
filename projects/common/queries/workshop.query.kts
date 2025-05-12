import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Encrypt
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite

class HttpResponse(underlyingNode: Node?) : Concept(underlyingNode)


class EncryptWithTexts(underlyingNode: Node?, concept: Cipher, key: Secret, val ciphertext: Any, val plaintext: Any) : Encrypt(underlyingNode, concept, key)

// key = "abc"
// ciphertext = encrypt("payload", key) // key has dataflow from line 44. We stop at "ciphertext".
// ciphertext = encrypt(key, ciphertext) // key has dataflow from "key" in line 45 but not from ciphertext.
// f = open("file.txt")
// f.write(key)
// f.write(ciphertext)

/** Secrets used as keys and all things derived from it must not be persisted (except from ciphertexts). */
fun statement1 (tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret>(
        sel = { secret ->
            dataFlow(
                startNode = secret,
                type = May,
                direction = Bidirectional(GraphToFollow.DFG),
                scope = Interprocedural(),
                predicate = { it is Encrypt },
            ).value
        },
        mustSatisfy = { secret ->
            // The secret must not be persisted.
            not(
                dataFlow(
                    startNode = secret,
                    type = May,
                    direction = Bidirectional(GraphToFollow.DFG),
                    scope = Interprocedural(),
                    earlyTermination = { dfg ->
                        tr.existsExtended<EncryptWithTexts>(
                            sel = { enc ->
                                not(
                                    dataFlow(secret,
                                        type = May,
                                        direction = Bidirectional(GraphToFollow.DFG),
                                        scope = Interprocedural(),
                                        predicate = { it != enc.key},
                                    )
                                ).value
                            },
                            mustSatisfy = { encrypt ->
                                QueryTree<Boolean>(value = encrypt.ciphertext == dfg)
                            }).value
                    },
                    // HttpEndpoint is probably not the best match -> introduce Http Response as concept.
                    predicate = { it is WriteFile || it is ReadFile || it is LogWrite || it is HttpResponse  },
                )
            )
        }
    )
}
