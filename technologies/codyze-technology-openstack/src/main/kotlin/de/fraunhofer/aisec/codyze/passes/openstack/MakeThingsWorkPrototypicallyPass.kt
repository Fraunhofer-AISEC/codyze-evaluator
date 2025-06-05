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
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
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
        identifyBarbicanGetSecretCall(t)
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

    /**
     * Tries to identify to the barbican API where the client aims to get an encryption key by the
     * id through the `castellan.key_manager` API.
     */
    fun identifyBarbicanGetSecretCall(t: TranslationResult) {
        val baseObjects =
            t.calls
                .filter { it.code == "key_manager.API(CONF)" }
                .flatMap { /* This is the variable/reference the return value is assigned to */
                    it.nextDFG.mapNotNull { (it as? Reference)?.refersTo as? VariableDeclaration }
                }
        val clientRequests =
            baseObjects.flatMap {
                // This call generates a new HttpClient
                val httpClient =
                    newHttpClient(
                            underlyingNode = it,
                            isTLS = false,
                            authentication = null,
                            connect = true,
                        )
                        .apply {
                            this.nextDFG += it
                            this.prevDFG += it
                        }
                // Find usage of the object as a base for a HttpRequest. Heuristics: The object
                // refersTo the same declaration
                val getCalls =
                    it.usages
                        .filter {
                            (it.astParent as? MemberExpression)?.base == it &&
                                it.astParent?.name?.localName == "get"
                        }
                        .mapNotNull { it.astParent?.astParent as? MemberCallExpression }
                getCalls.map {
                    // Create the HttpRequest operation for each of these calls.
                    // We "know" that all calls end up in /v1/secrets/{encryption_key_id}/payload
                    val request =
                        newHttpRequest(
                            underlyingNode = it,
                            url = "/v1/secrets/{secret_id}/payload",
                            arguments = it.arguments,
                            httpMethod = HttpMethod.GET,
                            concept = httpClient,
                            connect = true,
                        )
                    it.prevDFG += request
                    request
                }
            }

        t.allChildrenWithOverlays<HttpEndpoint>()
            .filter {
                it.httpMethod == HttpMethod.GET && it.path == "/v1/secrets/{secret_id}/payload"
            }
            .forEach { httpEndpoint ->
                clientRequests.forEach { clientRequest ->
                    clientRequest.to += httpEndpoint
                    clientRequest.prevDFG += httpEndpoint
                }
            }
    }
}
