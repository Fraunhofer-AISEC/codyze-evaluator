/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.TranslationResult
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod
import de.fraunhofer.aisec.cpg.graph.concepts.http.newHttpClient
import de.fraunhofer.aisec.cpg.graph.concepts.http.newHttpRequest
import de.fraunhofer.aisec.cpg.graph.declarations.VariableDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.TranslationResultPass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.passes.http.HttpPecanLibPass

@DependsOn(SymbolResolver::class)
@DependsOn(SecretPass::class)
@DependsOn(HttpPecanLibPass::class)
@DependsOn(OsloConfigPass::class)
class SecureKeyRetrievalPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun cleanup() {
        // Nothing to do here
    }

    override fun accept(t: TranslationResult) {
        identifyCastellanGetSecretCall(t)
    }

    /**
     * Tries to identify to the barbican API where the client aims to get an encryption key by the
     * id through the `castellan.key_manager` API.
     */
    fun identifyCastellanGetSecretCall(t: TranslationResult) {
        val baseObjects =
            t.calls
                .filter { it.code == "key_manager.API(CONF)" }
                .flatMap { /* This is the variable/reference the return value is assigned to */
                    it.nextDFG.mapNotNull { (it as? Reference)?.refersTo as? VariableDeclaration }
                }

        /**
         * Check if the `verify_ssl` option under the `[barbican]` section in the `cinder.conf` file
         * is set to `true` to enforce secure TLS requests. See
         * [Openstack docs](https://docs.openstack.org/cinder/rocky/configuration/block-storage/samples/cinder.conf.html)
         */
        val isTLS =
            t.records
                .filter {
                    it.name.localName == "barbican" && it.language.name.localName == "IniLanguage"
                }
                .flatMap { it.fields.filter { field -> field.name.localName == "verify_ssl" } }
                .all { (it.initializer as? Literal<*>)?.value == true }

        val clientRequests =
            baseObjects.flatMap {
                // This call generates a new HttpClient
                val httpClient =
                    newHttpClient(underlyingNode = it, isTLS = isTLS, authentication = null)
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
