# Examples of concepts and operations and tagging logic

```kotlin
class HttpResponse(underlyingNode: Node?, val httpEndpoint: HttpEndpoint) : Concept(underlyingNode)


class EncryptWithTexts(underlyingNode: Node?, concept: Cipher, key: Secret, val ciphertext: Any, val plaintext: Any) : Encrypt(underlyingNode, concept, key)

class BlockCipherKey(underlyingNode: Node? = null): Concept(underlyingNode)

class PlaintextBackupEndpoint(
    underlyingNode: FunctionDeclaration? = null, httpMethod: HttpMethod,
    path: String,
    arguments: List<Node>,
    authentication: Authentication?,
    authorization: Authorization?
): HttpEndpoint(underlyingNode, httpMethod, path, arguments, authentication, authorization)

tag {
    each<Node>( predicate = {it.overlays.any { it is BlockCipherKey } }).with { Secret() }

    each<FunctionDeclaration>(predicate = TODO()).with { PlaintextBackupEndpoint() }
}
```

# Examples of queries

```kotlin

// Use of variables which should be used in the queries. Benefit: No need to change the queries if the variables/State of the art change.
val goodCrypto = listOf<String>("AES", "X25519", "Ed25519", "SHA256", "SHA512")

/** Secrets used as keys and all things derived from it must not be persisted (except from ciphertexts). */
fun secretKeysDoNotLeaveTheSystem (tr: TranslationResult): QueryTree<Boolean> {
    return tr.allExtended<Secret>(
        sel = { secret ->
            // The secret is a key if it's used in an encryption function.
            dataFlow(
                startNode = secret,
                type = May,
                direction = Bidirectional(GraphToFollow.DFG),
                scope = Interprocedural(),
                predicate = { it is Encrypt },
            ).value
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
                    predicate = { it is WriteFile || it is ReadFile || it is LogWrite || (it is HttpResponse && it.httpEndpoint !is PlaintextBackupEndpoint)  },
                )
            )
        }
    )
}

/**
 * Returns `true` if the parameter `secret` is only used as a key in the encryption function.
 */
fun onlyUsedAsKey(tr: TranslationResult, node: Node, secret: Secret): Boolean {
    return tr.existsExtended<EncryptWithTexts>(
        sel = { enc -> // enc are all "EncryptWithTexts" operations in the translation result.
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
            QueryTree<Boolean>(value = encrypt.ciphertext === node)
        }).value
}
```