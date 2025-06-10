/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.openstack

import de.fraunhofer.aisec.codyze.openstack.passes.PythonMemoryPass
import de.fraunhofer.aisec.codyze.passes.concepts.crypto.encryption.openstack.CinderKeyManagerSecretPass
import de.fraunhofer.aisec.codyze.passes.concepts.http.python.HttpPecanLibPass
import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*
import de.fraunhofer.aisec.cpg.passes.*
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

@DependsOn(ControlFlowSensitiveDFGPass::class)
@DependsOn(EvaluationOrderGraphPass::class)
@DependsOn(CinderKeyManagerSecretPass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(PythonMemoryPass::class)
class MakeThingsWorkPrototypicallyPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun cleanup() {
        // Nothing to do here
    }

    override fun accept(t: TranslationResult) {
        decryptedCertToSecret(t)
        getSecretPluginCall(t)
    }

    /**
     * Identifies the call to retrieve_plugin.get_secret() in barbican because this is where the key
     * is read e.g. from an HSM or something else (depending on the configuration).
     */
    fun decryptedCertToSecret(t: TranslationResult) {
        for (getSecretCall in
            t.mcalls({
                it.name.localName == "get_decrypted_private_key" &&
                    it.base?.name?.localName == "magnum_cert"
            })) {
            val secret = newSecret(underlyingNode = getSecretCall, connect = true)
            val getSecret =
                newGetSecret(underlyingNode = getSecretCall, concept = secret, connect = true)
                    .apply { this.nextDFG += getSecretCall }
        }
    }

    /**
     * Identifies the call to retrieve_plugin.get_secret() in barbican because this is where the key
     * is read e.g. from an HSM or something else (depending on the configuration).
     */
    fun getSecretPluginCall(t: TranslationResult) {
        for (getSecretCall in
            t.mcalls({
                it.name.localName == "get_secret" && it.base?.name?.localName == "retrieve_plugin"
            })) {
            val secret = newSecret(underlyingNode = getSecretCall, connect = true)
            val getSecret =
                newGetSecret(underlyingNode = getSecretCall, concept = secret, connect = true)
                    .apply { this.nextDFG += getSecretCall }
        }
    }
}
