/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.http

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Annotation
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequestHandler
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.get
import de.fraunhofer.aisec.cpg.graph.ifs
import de.fraunhofer.aisec.cpg.graph.invoke
import de.fraunhofer.aisec.cpg.graph.refs
import de.fraunhofer.aisec.cpg.graph.statements.expressions.AssignExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.BinaryOperator
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.openstack.concepts.newHttpEndpoint
import de.fraunhofer.aisec.openstack.concepts.newHttpRequestHandler
import de.fraunhofer.aisec.openstack.concepts.newRegisterHttpEndpoint

@DependsOn(SymbolResolver::class)
class HttpPecanLibPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun cleanup() {
        //
    }

    override fun accept(component: Component) {
        /**
         * Pecan application object, created using
         * (`pecan.Pecan`)(https://pecan.readthedocs.io/en/latest/pecan_core.html). *
         */
        val pecanApp = component.calls("build_wsgi_app").firstOrNull()
        if (pecanApp != null) {
            // First argument is base Controller
            val controller =
                (pecanApp.arguments.first() as ConstructExpression).instantiates
                    as RecordDeclaration
            val versionId = controller.refs["version_id"]
            val basePath =
                ((versionId?.astParent as AssignExpression).rhs.firstOrNull() as Literal<*>)
                    .value
                    .toString()

            // Register endpoints of base Controller
            registerEndpointsFromController(controller = controller, basePath = basePath)

            // The default Controller registers the Sub-Controller and their endpoints
            val initMethod = controller.constructors.firstOrNull()
            if (initMethod != null) {
                val subControllers =
                    initMethod.calls.filterIsInstance<ConstructExpression>().map {
                        it.instantiates as RecordDeclaration
                    }
                for (subController in subControllers) {
                    val subBasePath = "/$basePath/${subController.name.localName.toKebabCase()}"
                    registerEndpointsFromController(subController, subBasePath)
                }
            }
        }
    }

    private fun registerEndpointsFromController(controller: RecordDeclaration, basePath: String) {
        val requestHandler = newHttpRequestHandler(underlyingNode = controller, basePath = basePath)

        val annotatedMethods = controller.methods.filter { it.annotations.isNotEmpty() }

        for (method in annotatedMethods) {
            for (annotation in method.annotations) {
                when (annotation.name.toString()) {
                    "index.when" -> // Routing based on Request Method
                    handlePecanIndexWhenDecorator(annotation, method, requestHandler)

                    "pecan.expose" ->
                        if (
                            method.name.localName == "_lookup"
                        ) { // Routing to Subcontrollers with _lookup
                            handlePecanLookupMethod(method, requestHandler)
                        } else {
                            // Routing based on method name
                            handlePecanExpose(method, requestHandler)
                        }
                }
            }
        }
    }

    /**
     * Handles methods annotated with `@pecan.expose` to register them as HTTP endpoints. The
     * `index` method is ignored because it typically serves as the default route or entry point for
     * a controller, registering the controller itself but not acting as a specific HTTP endpoint.
     *
     * Instead, other methods with more specific names are registered as endpoints, see
     * [Pecan Decorators](https://pecan.readthedocs.io/en/latest/pecan_decorators.html#pecan-decorators).
     */
    private fun handlePecanExpose(method: MethodDeclaration, requestHandler: HttpRequestHandler) {
        if (method.name.localName == "index") return

        val methodName = method.name.localName
        val httpEndpoint =
            newHttpEndpoint(
                underlyingNode = method,
                httpMethod = "GET",
                path = "${requestHandler.basePath}/$methodName",
                arguments = method.parameters,
            )
        requestHandler.endpoints.add(httpEndpoint)

        newRegisterHttpEndpoint(
            underlyingNode = method,
            concept = requestHandler,
            httpEndpoint = httpEndpoint,
        )
    }

    /**
     * Handles the routing
     * [`_lookup`](https://pecan.readthedocs.io/en/latest/routing.html#routing-to-subcontrollers-with-lookup)
     * method in a Pecan Controller to register Sub-Controllers. It processes the method to
     * determine if it differentiates between sub-resources. In this case, we check if the parameter
     * is checked in a condition. Based on the parameter value:
     * - It registers Sub-Controllers if a new controller is instantiated.
     * - It extends the [HttpRequestHandler]s base path with the parameter value (e.g.,
     *   `/resource/{parameter}`).
     *
     * For each sub-resource or parameterized path, corresponding endpoints are registered and their
     * controllers are recursively processed to register all sub-controller.
     */
    private fun handlePecanLookupMethod(
        method: MethodDeclaration,
        requestHandler: HttpRequestHandler,
    ) {
        // Extract the first parameter and distinguish between handling a sub-resource or a specific
        // resource.
        val parameter = method.parameters.firstOrNull()?.name?.localName

        // Check if the parameter is used to differentiate between sub-resources
        val isParameterCheckedInIfs =
            method.ifs.any { ifStatement ->
                val condition = ifStatement.condition as? BinaryOperator
                val lhs = condition?.lhs as? Reference
                lhs?.name?.localName == parameter
            }

        // If it is not checked then it must be a specific parameter with a new endpoint
        if (!isParameterCheckedInIfs) {
            val controller =
                method.calls
                    .filterIsInstance<ConstructExpression>()
                    .firstOrNull { it.name.endsWith("Controller") }
                    ?.instantiates as? RecordDeclaration

            val basePath = "${requestHandler.basePath}/{$parameter}"
            if (controller != null) {
                registerEndpointsFromController(controller, basePath)
            }
            return
        }

        // Register the Sub-Controllers and their endpoints
        method.ifs.forEach { ifStatement ->
            val condition = ifStatement.condition as? BinaryOperator
            val lhs = condition?.lhs as? Reference

            if (lhs?.name?.localName == parameter) {
                val rhsValue = (condition?.rhs as? Literal<*>)?.value
                val basePath = "${requestHandler.basePath}/$rhsValue"
                val controller =
                    ifStatement.thenStatement.calls
                        .filterIsInstance<ConstructExpression>()
                        .firstOrNull { it.name.endsWith("Controller") }
                        ?.instantiates as? RecordDeclaration

                if (controller != null) {
                    registerEndpointsFromController(controller, basePath)
                }
            }
        }
    }

    /**
     * Handles the
     * [`@index.when()`](https://pecan.readthedocs.io/en/latest/routing.html#routing-based-on-request-method)
     * decorator, extracting the HTTP method and registering the endpoint.
     */
    private fun handlePecanIndexWhenDecorator(
        node: Annotation,
        method: MethodDeclaration,
        requestHandler: HttpRequestHandler,
    ) {
        /**
         * First argument of
         * [`@index.when()`]((https://pecan.readthedocs.io/en/latest/pecan_decorators.html) contains
         * the HTTP method.*
         */
        val httpMethod = (node.members.first().value as Literal<*>).value.toString()

        val httpEndpoint =
            newHttpEndpoint(
                underlyingNode = method,
                httpMethod = httpMethod,
                path = requestHandler.basePath,
                arguments = method.parameters,
            )
        requestHandler.endpoints.add(httpEndpoint)

        newRegisterHttpEndpoint(
            underlyingNode = method,
            concept = requestHandler,
            httpEndpoint = httpEndpoint,
        )
    }

    /**
     * Converts a Controller name into a URL-friendly format. It removes the 'Controller' suffix and
     * converts the remaining string into kebab-case.
     */
    fun String.toKebabCase(): String {
        return this.replace("Controller", "").replace(Regex("([a-z])([A-Z])"), "$1-$2").lowercase()
    }
}
