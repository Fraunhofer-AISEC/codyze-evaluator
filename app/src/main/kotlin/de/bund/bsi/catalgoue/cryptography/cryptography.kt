package de.bund.bsi.catalgoue.cryptography

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration


/*
    Concepts
*/

// Asymmetric Cryptography

open class AsymmetricScheme(underlyingNode: Node?) : Concept (underlyingNode = underlyingNode) {

    var privateKey : PrivateKey? = null;
    var publicKey : PublicKey? = null;

}

open class PrivateKey(un: Node?) : Concept(underlyingNode = un)
open class PublicKey(un: Node?) : Concept(underlyingNode = un)
open class AsymmetricCiphertext(underlyingNode: Node?) : Concept(underlyingNode = underlyingNode)
open class AsymmetricEncrypt(un: Node?) : FunctionDeclaration()
open class AsymmetricSharedSecret(un: Node?) : Concept(underlyingNode = un)
//Can we tag a function such that it has to return a specific type and accept (at least) some specific types?
open class AsymmetricDecrypt(un: Node?) : Concept(un){

    fun decrypt(ctxt: AsymmetricCiphertext, pk: PrivateKey) : AsymmetricSharedSecret{
        TODO()
    }
}

open class AsymmetricKeyGenerator(un: Node?) : Concept(un){
    fun generate(rand: Randomness) : Pair<PublicKey, PrivateKey>{
        return TODO()
    }
}

//Symmetric Cryptography

//shall return a "KeyMaterial" Concept
open class KeyGenerator(un: Node) : Concept(un) {
    fun generate(rand: Randomness) : Blockipherkey{TODO()}
}

open class Blockipherkey(un: Node?) : Concept(un)

//Can we tag a function such that it has to return a specific type and accept (at least) some specific types?
open class SymmetricEncrypt(un: Node?) : Concept(un){
    fun encrypt(ptxt: Any?, key: Blockipherkey) : Any? {
        TODO()
    }
}

//Can we tag a function such that it has to return a specific type and accept (at least) some specific types?
open class SymmetricDecrypt(un: Node?) : Concept(un){
    fun decrypt(ctxt: Any?, key: Blockipherkey) : Any? {
        TODO()
    }
}

open class MessageAuthenticationCode(un: Node?) : Concept(un)


//No-key-cryptography
open class Randomness(un: Node?) : Concept(un)
open class RandomnessSource(un: Node?) : Concept(un) {
    fun sample() : Randomness{
        return TODO()
    }
}
open class Hashfunction(un: Node?) : Concept(un)
open class EntropyPreservingFunction(un: Node?) : Concept(un)


/*
    Derived Concepts
*/
class FrodoKEM(un: Node?) : AsymmetricScheme(un)
class FrodoKEMCiphertext(un: Node?) : AsymmetricCiphertext(un)
class AES256Encrypt(un: Node?) : SymmetricEncrypt(un)
class HMAC(un: Node?) : EntropyPreservingFunction(un) //TODO: Must also be a MessageAuthenticationCode!! Maybe tagging every node that is hmac with MAC using the tagging api afterwards?

/*
    Generic Tags & Queries
*/

// All Blockcipherkeys are secret
// A blockcipherkey must be the result of a KeyGenerator
// There must not be any dataflow from a blockcipherkey to a variable that is not used as the key-parameter of a blockcipher
// If there is a write-operation into a randomness-object, it must happen inside an "entropy-preserving-function" (i.e. during key derivation: KEMs expect a 256 Bit string, Randomness-Sources do not output these)

