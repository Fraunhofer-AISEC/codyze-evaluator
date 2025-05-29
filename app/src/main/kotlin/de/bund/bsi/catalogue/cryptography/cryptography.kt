/*
 * This file is part of the OpenStack Checker
 */
package de.bund.bsi.catalogue.cryptography

import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.concepts.Concept
import de.fraunhofer.aisec.cpg.graph.concepts.Operation

/*
    Concepts
*/

// Asymmetric Cryptography

open class AsymmetricScheme(underlyingNode: Node?) : Concept(underlyingNode = underlyingNode) {

    var privateKey: PrivateKey? = null

    var publicKey: PublicKey? = null
}

open class PrivateKey(un: Node?) : Concept(underlyingNode = un)

open class PublicKey(un: Node?) : Concept(underlyingNode = un)

open class AsymmetricSharedSecret(un: Node?) : Concept(underlyingNode = un)

open class AsymmetricCiphertext(underlyingNode: Node?) : Concept(underlyingNode = underlyingNode)


open class AsymmetricScheme_generateKey(un: Node?) : Operation(un, AsymmetricScheme(un)) {
    fun generate(rand: Randomness): Pair<PublicKey, PrivateKey> {
        return TODO()
    }
}

open class AsymmetricEncrypt(un: Node?) : Operation(un, AsymmetricScheme(un))

// Can we tag a function such that it has to return a specific type and accept (at least) some
// specific types?
open class AsymmetricDecrypt(un: Node?) : Operation(un, AsymmetricScheme(un)) {

    fun decrypt(ctxt: AsymmetricCiphertext, pk: PrivateKey): AsymmetricSharedSecret {
        TODO()
    }
}



// Symmetric Cryptography

open class SymmetricScheme(un: Node?) : Concept(un)
// shall return a "KeyMaterial" Concept
open class KeyGenerator(un: Node?) : Concept(un)
open class SymmetricScheme_generateKey(un: Node?, rand: Randomness): Operation(un, KeyGenerator(un))

open class Blockcipherkey(un: Node?) : Concept(un)

// Can we tag a function such that it has to return a specific type and accept (at least) some
// specific types?
open class SymmetricEncrypt(un: Node?, plaintext: Any, key: Blockcipherkey) : Operation(un, SymmetricScheme(un)) {
    var key: Blockcipherkey = key
    var plaintext: Any = plaintext
}

// Can we tag a function such that it has to return a specific type and accept (at least) some
// specific types?
open class SymmetricDecrypt(un: Node?) : Operation(un, SymmetricScheme(un)) {
    fun decrypt(ctxt: Any?, key: Blockcipherkey): Any? {
        TODO()
    }
}


open class MessageAuthenticationCode(un: Node?) : Concept(un)

// No-key-cryptography
open class Randomness(un: Node?) : Concept(un)

open class RandomnessSource(un: Node?) : Concept(un)
open class Randomness_sample(un: Node?) : Operation(un, RandomnessSource(un))

open class Hashfunction(un: Node?) : Concept(un)

open class EntropyPreservingFunction(un: Node?) : Concept(un)

// meta-security
/** Makes sure, that a key is not used in a way conflicting with a security policy.
 This includes checking the number of invocations using a key, or its lifetime*/
open class UsageRestrictingModule(un: Node?) : Concept(un)

/*
    Derived Concepts
*/
class FrodoKEM(un: Node?) : AsymmetricScheme(un)

class FrodoKEMCiphertext(un: Node?) : AsymmetricCiphertext(un)

class AES256Encrypt(un: Node?, Plaintext: Any, Key: Blockcipherkey) :
    SymmetricEncrypt(un, Plaintext, Key)

class HMAC(un: Node?) : EntropyPreservingFunction(un)

/*

   Protocols

*/

// Wireguard
open class Wireguard_CryptoKeyRoutingTable(un: Node?) : Concept(un)

open class Wireguard_KeyStore


