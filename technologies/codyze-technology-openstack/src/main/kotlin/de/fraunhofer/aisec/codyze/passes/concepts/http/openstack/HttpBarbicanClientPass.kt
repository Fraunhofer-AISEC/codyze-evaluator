/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.http.openstack

import de.fraunhofer.aisec.codyze.passes.concepts.http.mapHttpMethod
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.*
import de.fraunhofer.aisec.cpg.graph.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.statements.expressions.*
import de.fraunhofer.aisec.cpg.passes.*
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn

/**
 * This pass registers HTTP endpoints from the [PythonBarbicanClient]. The [PythonBarbicanClient] is
 * a library used to interact with [Barbican].
 *
 * The library follows HATEOAS, meaning that endpoints are discovered dynamically through hypermedia
 * links instead of fixed URLs. This makes it challenging to register all endpoints.
 *
 * However, we can extract base paths from the manager classes, as they extend
 * `base.BaseEntityManager`, which takes an entity name (e.g., 'secrets' for `SecretManager`) as a
 * constructor argument.
 *
 * The `Client` class registers these manager classes and provides them with an `_HTTPClient`
 * instance. This `_HTTPClient` extends `keystoneauth1.adapter.Adapter`, which provides the HTTP
 * request methods.
 */
@DependsOn(SymbolResolver::class)
class HttpBarbicanClientPass(ctx: TranslationContext) : TranslationResultPass(ctx) {
    override fun accept(t: TranslationResult) {
        // The client class initializes and registers the manager classes
        // (SecretManager, OrderManager, etc.) to handle different API resources.
        // These managers also use the shared HTTP client instance.
        val client = t.records["Client"]
        client?.let {
            val initMethod = client.constructors.firstOrNull()
            if (initMethod != null) {
                val managers =
                    initMethod.calls.filterIsInstance<ConstructExpression>().mapNotNull {
                        (it.instantiates as? RecordDeclaration)?.takeIf {
                            it.name.localName.endsWith("Manager") == true
                        }
                    }

                for (manager in managers) {
                    registerRequests(manager)
                }
            }
        }
    }

    /** Registers the requests of the manager. */
    private fun registerRequests(manager: RecordDeclaration) {
        val client =
            newHttpClient(
                underlyingNode = manager,
                isTLS = false,
                authentication = null,
                connect = true,
            )

        val constructor = manager.constructors.firstOrNull()
        val initCall =
            constructor?.calls?.filterIsInstance<MemberCallExpression>()?.firstOrNull {
                it.callee is MemberExpression && it.name.localName == "__init__"
            }

        val basePath =
            initCall?.arguments?.getOrNull(1)?.let {
                when (it) {
                    is Literal<*> -> it.evaluate() as? String
                    is MemberExpression -> {
                        val record =
                            it.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                                    it is RecordDeclaration
                                }
                                .fulfilled
                                .map { it.nodes.last() }
                                .firstOrNull()

                        val field =
                            record?.fields?.find { field ->
                                field.name.localName == it.name.localName
                            }

                        field?.evaluate() as? String
                    }

                    else -> null
                }
            }

        val crudMethods = setOf("create", "update", "delete", "get")
        for (method in manager.methods) {
            if (method.name.localName in crudMethods) {
                newHttpRequest(
                    underlyingNode = method,
                    concept = client,
                    url = basePath ?: "",
                    arguments = method.parameters,
                    httpMethod = mapHttpMethod(method.name.localName),
                    connect = true,
                )
            }
        }
    }

    override fun cleanup() {
        // Nothing to do here
    }
}
