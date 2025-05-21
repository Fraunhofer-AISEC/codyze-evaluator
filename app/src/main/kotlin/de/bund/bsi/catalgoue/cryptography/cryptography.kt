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
open class KEMSharedSecret(un: Node?) : Concept(underlyingNode = un)

//Can we tag a function such that it has to return a specific type and accept (at least) some specific types?
open class AsymmetricDecrypt(un: Node?) : Concept(un){

    fun decrypt(ctxt: AsymmetricCiphertext, pk: PrivateKey) : KEMSharedSecret{
        TODO()
    }
}



//Symmetric Cryptography

//shall return a "KeyMaterial" Concept
open class KeyGenerator(un: Node) : Concept(un)

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


/*
    Derived Concepts
*/
class FrodoKEM(un: Node?) : AsymmetricScheme(un)
class FrodoKEMCiphertext(un: Node?) : AsymmetricCiphertext(un)
class AES256Encrypt(un: Node?) : SymmetricEncrypt(un)


/*
    Generic Tags & Queries
*/

// All Blockcipherkeys are secret
// A blockcipherkey must be the result of a KeyGenerator
// There must not be any dataflow from a blockcipherkey to a variable that is not used as the key-parameter of a blockcipher
// ...

