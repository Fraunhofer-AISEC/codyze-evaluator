/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.openstack.passes

import de.fraunhofer.aisec.codyze.openstack.passes.http.HttpPecanLibPass
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.newCipher
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.newGetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.newSecret
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.CreateEncryptedDisk
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.newCreateEncryptedDisk
import de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.newDiskEncryption
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.http.newHttpClient
import de.fraunhofer.aisec.cpg.graph.concepts.http.newHttpRequest
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.edges.get
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ControlFlowSensitiveDFGPass
import de.fraunhofer.aisec.cpg.passes.EvaluationOrderGraphPass
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

@DependsOn(ControlFlowSensitiveDFGPass::class)
@DependsOn(EvaluationOrderGraphPass::class)
@DependsOn(SecretPass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(PythonMemoryPass::class)
class MakeThingsWorkPrototypicallyPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun cleanup() {
        // Nothing to do here
    }

    override fun accept(t: TranslationResult) {
        decryptedCertToSecret(t)
        identifyBarbicanGetSecretCall(t)
        // findDiskEncryptionOperations(t)
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
     * Generates a [CreateEncryptedDisk] operation for a call to execute with arguments "cryptsetup"
     * and "luksFormat" and sets the key input and the cipher.
     */
    fun findDiskEncryptionOperations(t: TranslationResult) {
        for (executeCall in t.calls("execute")) {
            val arguments = executeCall.arguments.map { it.evaluate() }
            if ("luksFormat" in arguments && "cryptsetup" in arguments) {
                val keyArgument = executeCall.argumentEdges["process_input"]?.end
                val secrets =
                    keyArgument
                        ?.followDFGEdgesUntilHit(
                            collectFailedPaths = false,
                            findAllPossiblePaths = false,
                        ) {
                            it.overlays.any { it is Secret }
                        }
                        ?.fulfilled
                        ?.map { it.nodes.last() }
                        ?.flatMap { it.overlays.filterIsInstance<Secret>() }

                // There are two keys (one is dervied from the other), we need to take the "new_key"
                // (we need to differentiate between the two somehow or adjust our queries)
                val key = secrets?.firstOrNull() { it.name.localName == "Key[new_key]" }

                // This call creates a new encrypted block storage
                val argumentOfCipher =
                    executeCall.arguments[arguments.indexOfFirst { it == "--cipher" } + 1]
                // TODO: Fill the properties of cipher
                val cipher = newCipher(argumentOfCipher, connect = true)
                val diskEncryption =
                    newDiskEncryption(
                            underlyingNode = executeCall,
                            cipher = cipher,
                            key = key,
                            connect = true,
                        )
                        .apply { this.prevDFG += executeCall }

                // val secretInput = executeCall.arguments[arguments.indexOfFirst { "--key-file" in
                // ((it as? String) ?: "") } + 1]
                /*val secretInput =
                    executeCall.argumentEdges.firstOrNull { it.name == "process_input" }?.end
                secretInput?.let {
                    val secret = Secret(secretInput).codeAndLocationFrom(secretInput)
                    diskEncryption.key = secret
                    // Also add the DFG
                    secret.prevDFG += secretInput
                }*/

                newCreateEncryptedDisk(
                        underlyingNode = executeCall,
                        concept = diskEncryption,
                        connect = true,
                    )
                    .apply {
                        // This probably makes it "too" easy?
                        // diskEncryption.key?.let { this.prevDFG += it }
                        this.prevDFG += executeCall
                    }
            }
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
