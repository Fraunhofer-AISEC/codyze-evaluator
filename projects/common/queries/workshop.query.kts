import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication
import de.fraunhofer.aisec.cpg.graph.concepts.auth.Authorization
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Encrypt
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.file.ReadFile
import de.fraunhofer.aisec.cpg.graph.concepts.file.WriteFile
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.logging.LogWrite
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.passes.concepts.each
import de.fraunhofer.aisec.cpg.passes.concepts.tag
import de.fraunhofer.aisec.cpg.passes.concepts.with



class EncryptWithTexts(underlyingNode: Node?, concept: Cipher, key: Secret, val ciphertext: Any, val plaintext: Any) : Encrypt(underlyingNode, concept, key)


// key = "abc"
// ciphertext = encrypt("payload", key) // key has dataflow from line 44. We stop at "ciphertext".
// ciphertext = encrypt(key, ciphertext) // key has dataflow from "key" in line 45 but not from ciphertext.
// f = open("file.txt")
// f.write(key)
// f.write(ciphertext)



// Use of variables which should be used in the queries. Benefit: No need to change the queries if the variables/State-of-the-art change.
val goodCrypto = listOf<String>("AES", "X25519", "Ed25519", "SHA256", "SHA512")

class BlockCipherKey(underlyingNode: Node? = null): Concept(underlyingNode)




