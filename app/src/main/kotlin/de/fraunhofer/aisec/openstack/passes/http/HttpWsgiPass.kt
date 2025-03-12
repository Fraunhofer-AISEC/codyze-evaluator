/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.http

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.assigns
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequestHandler
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.edges.get
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.records
import de.fraunhofer.aisec.cpg.graph.returns
import de.fraunhofer.aisec.cpg.graph.statements
import de.fraunhofer.aisec.cpg.graph.statements.expressions.AssignExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.BinaryOperator
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.InitializerListExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.KeyValueExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Literal
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.graph.statements.expressions.SubscriptExpression
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate
import de.fraunhofer.aisec.openstack.concepts.newHttpEndpoint
import de.fraunhofer.aisec.openstack.concepts.newHttpRequestHandler
import de.fraunhofer.aisec.openstack.concepts.newRegisterHttpEndpoint

@DependsOn(SymbolResolver::class)
@ExecuteLate
class HttpWsgiPass(ctx: TranslationContext) : ComponentPass(ctx) {
    val apiVersionPath = "/v3"

    override fun cleanup() {
        //
    }

    override fun accept(component: Component) {
        /**
         * Find API Router. For now, we assume that:
         * - API version is v3
         * - The entry point is 'router.py' - which is typically defined in the api-paste.ini file
         *
         * In the future, the implementation can also be extended to read out the values from the
         * config files. See (Openstack
         * Checker)[https://github.com/orgs/Fraunhofer-AISEC/projects/17/views/2?pane=issue&itemId=95467628&issue=Fraunhofer-AISEC%7Copenstack-checker%7C50]
         *
         * Reference how the routing is handled through the
         * [WSGI Module](https://docs.openstack.org/cinder/latest/contributor/api/cinder.api.openstack.wsgi.html).
         *
         * See also the official
         * [API Reference V3](https://docs.openstack.org/api-ref/block-storage/v3/)
         */
        val apiRouter =
            component.translationUnits
                .find { it.name.toString().contains("router.py") }
                ?.records
                ?.firstOrNull()
        apiRouter?.let { router ->
            val resourceCalls =
                router.assigns
                    .filter { assign ->
                        (assign.rhs.firstOrNull() as? CallExpression)?.name?.localName ==
                            "create_resource"
                    }
                    .mapNotNull { assign ->
                        val resourceKey =
                            (assign.lhs.firstOrNull() as? SubscriptExpression)
                                ?.subscriptExpression
                                ?.let { it.evaluate() as? String }

                        resourceKey?.let { key ->
                            val callExpression = assign.rhs.firstOrNull() as? CallExpression
                            if (callExpression != null) {
                                val controller = getControllerFromCreateResource(callExpression)
                                controller?.let { key to it }
                            } else {
                                null
                            }
                        }
                    }

            for ((resourceKey, controller) in resourceCalls) {
                // In some cases, the registered controllers are assigned to other variables.
                // Such assignments are then used to extend the parent controller with additional
                // endpoints.
                val aliases =
                    router.assigns
                        .filter { assign ->
                            (assign.rhs.firstOrNull() as? SubscriptExpression)
                                ?.subscriptExpression
                                ?.let { it.evaluate() as? String } == resourceKey
                        }
                        .mapNotNull { (it.lhs.firstOrNull() as? Reference)?.name?.localName }

                // Gathers related calls that reference the same controller via its reference or
                // original assignment.
                // In addition to the endpoint registrations via `resource()`, this also includes
                // the specific ones via 'connect()`.
                val relatedCalls =
                    router.calls.filter { call ->
                        val controllerArg = call.argumentEdges["controller"]?.end
                        when (controllerArg) {
                            is SubscriptExpression -> {
                                (controllerArg.subscriptExpression.evaluate() as? String) ==
                                    resourceKey
                            }

                            is Reference -> {
                                val refName = (controllerArg).name.localName
                                refName in aliases
                            }

                            else -> false
                        }
                    }
                if (relatedCalls.isNotEmpty()) {
                    handleBaseRoutes(controller, relatedCalls)
                }
            }
            // For some endpoints there are Extensions defined which extend the endpoints
            val resourceExtensionCalls =
                component.calls.filter {
                    it.name.localName == "ResourceExtension" &&
                        it.name.parent?.localName == "extensions"
                }
            val resourceControllers = resourceCalls.map { it.second }
            handleExtensionRoutes(resourceExtensionCalls, resourceControllers)
        }
    }

    /**
     * Handles routes related to resource extensions, ensuring that also the extended endpoints are
     * registered. See also
     * [Extensions module](https://docs.openstack.org/cinder/latest/contributor/api/cinder.api.extensions.html)
     */
    private fun handleExtensionRoutes(
        resourceExtensionCalls: List<CallExpression>,
        resourceControllers: List<RecordDeclaration>,
    ) {
        for (resourceExtensionCall in resourceExtensionCalls) {
            val extensionController = getControllerFromResourceExtension(resourceExtensionCall)
            if (extensionController != null) {
                // Check if controller is already registered
                val isAlreadyRegistered =
                    resourceControllers.any { registeredController ->
                        registeredController.name.localName == extensionController.name.localName
                    }
                if (isAlreadyRegistered) {
                    continue
                }
                handleResourceExtension(
                    node = resourceExtensionCall,
                    controller = extensionController,
                )
            }
        }
    }

    /**
     * Second argument of
     * [`ResourceExtension`](https://docs.openstack.org/cinder/latest/contributor/api/cinder.api.extensions.html#cinder.api.extensions.ResourceExtension)
     * is always the referenced Controller *
     */
    private fun getControllerFromResourceExtension(call: CallExpression): RecordDeclaration? {
        val controllerArg = call.arguments.getOrNull(1)
        return when (controllerArg) {
            is Reference -> {
                val ref = controllerArg.refersTo
                val construct =
                    (ref?.astParent as? AssignExpression)?.rhs?.firstOrNull()
                        as? ConstructExpression
                construct?.instantiates as? RecordDeclaration
            }

            is ConstructExpression -> controllerArg.instantiates as? RecordDeclaration
            else -> null
        }
    }

    /**
     * Handles the base routes for a given resource controller, registering the CRUD endpoints and
     * other specialized routes such as 'connect' or additional actions.
     */
    private fun handleBaseRoutes(controller: RecordDeclaration, calls: List<CallExpression>) {
        val basePath =
            if (calls.any { extractEndpointPath(call = it, argumentIndex = 1) == "/" }) {
                "/"
            } else {
                apiVersionPath
            }
        val requestHandler = newHttpRequestHandler(controller, basePath)

        calls.forEach { call ->
            when (call.name.localName) {
                "resource" ->
                    handleResource(
                        call = call,
                        controller = controller,
                        requestHandler = requestHandler,
                    )

                "connect" ->
                    handleConnect(
                        call = call,
                        controller = controller,
                        requestHandler = requestHandler,
                    )
            }
        }
    }

    /**
     * Handles the `actions` and `conditions` on a controller. See
     * [OpenStack API](https://docs.openstack.org/cinder/latest/contributor/addmethod.openstackapi.html#routing)
     */
    private fun handleConnect(
        call: CallExpression,
        controller: RecordDeclaration,
        requestHandler: HttpRequestHandler,
    ) {
        val extractedEndpointPath = extractEndpointPath(call = call, argumentIndex = 1)
        val endpoint =
            if (requestHandler.basePath == "/") {
                requestHandler.basePath
            } else {
                "${requestHandler.basePath}/$extractedEndpointPath"
            }

        // We need to extract the HTTP Method from the conditions, e.g. `conditions={"method":
        // ['PUT']}`
        val conditions = call.argumentEdges["conditions"]?.end as? InitializerListExpression
        val httpMethod =
            conditions
                ?.initializers
                ?.filterIsInstance<KeyValueExpression>()
                ?.firstOrNull { (it.key as? Literal<*>)?.value?.toString() == "method" }
                ?.value
                ?.let { it as? InitializerListExpression }
                ?.initializers
                ?.single()
                ?.let { it.evaluate() as? String }

        // Extract the name of the action which is usually also the name of the method itself, e.g.
        // `action='update_all'`.
        val methodName = (call.argumentEdges["action"]?.end as? Literal<*>)?.value?.toString()
        if (methodName != "action") {
            controller.methods
                .find { it.name.localName == methodName }
                ?.let {
                    registerHttpEndpoints(
                        method = it,
                        requestHandler = requestHandler,
                        path = endpoint,
                        httpMethod = httpMethod,
                    )
                }
        } else {
            // In some cases, when only `action` is defined,
            // multiple endpoints are registered through the `action` annotation, and they all point
            // to the same URL.
            val annotatedMethods =
                controller.methods.filter { method ->
                    method.annotations.any { it.name.localName == methodName }
                }
            if (annotatedMethods.isNotEmpty()) {
                annotatedMethods.forEach { method ->
                    if (
                        endpoint.contains("id", ignoreCase = true) &&
                            method.parameters.any {
                                it.name.localName.equals("id", ignoreCase = true)
                            }
                    ) {
                        registerHttpEndpoints(
                            method = method,
                            requestHandler = requestHandler,
                            path = endpoint,
                            httpMethod = httpMethod,
                        )
                    } else {
                        registerHttpEndpoints(
                            method = method,
                            requestHandler = requestHandler,
                            path = endpoint,
                            httpMethod = httpMethod,
                        )
                    }
                }
            }
        }
    }

    /**
     * Handles the resource-related routes (e.g., CRUD operations) and registers them for the
     * specified controller. It handles dynamic paths, especially when a parent resource is
     * involved. See
     * [OpenStack API](https://docs.openstack.org/cinder/latest/contributor/addmethod.openstackapi.html#routing)
     */
    private fun handleResource(
        call: CallExpression,
        controller: RecordDeclaration,
        requestHandler: HttpRequestHandler,
    ) {
        val apiEndpoint = extractEndpointPath(call = call, argumentIndex = 1)

        // Check if the resource has a parent
        val parentResource = call.argumentEdges["parent_resource"]?.end as? ConstructExpression
        val parentResourcePath =
            parentResource?.let {
                val memberName =
                    it.argumentEdges["member_name"]?.end.let { arg ->
                        (arg as? Literal<*>)?.value?.toString()
                    }
                val collectionName =
                    it.argumentEdges["collection_name"]?.end.let { arg ->
                        (arg as? Literal<*>)?.value?.toString()
                    }
                if (memberName != null && collectionName != null) {
                    "$collectionName/{${memberName}_id}/$apiEndpoint"
                } else {
                    null
                }
            }
        var basePath = requestHandler.basePath
        basePath +=
            if (parentResourcePath != null) {
                "/$parentResourcePath"
            } else {
                "/$apiEndpoint"
            }
        // Register CRUD methods (create, update, delete, show, index)
        registerEndpointsOfCrudMethods(
            methods = controller.methods,
            requestHandler = requestHandler,
            basePath = basePath,
        )

        // The collection variable represents a mapping of actions to HTTP methods, e.g.
        // `collection = {'detail': 'GET'}` means the "detail" action is accessed via a GET request.
        val collection = call.argumentEdges["collection"]?.end as? InitializerListExpression
        collection?.initializers?.filterIsInstance<KeyValueExpression>()?.forEach { keyValue ->
            val methodName = (keyValue.key as? Literal<*>)?.value?.toString()
            val httpMethod = (keyValue.value as? Literal<*>)?.value?.toString()

            if (methodName != null && httpMethod != null) {
                // Try to find the method in the current controller
                var method = controller.methods.find { it.name.localName == methodName }

                // If not found, check in the superclasses
                if (method == null) {
                    for (superClass in
                        controller.superClasses.filterIsInstance<RecordDeclaration>()) {
                        // Ignore base controllers
                        if (
                            !superClass.name.localName.contains("wsgi.Controller") &&
                                superClass.name.localName.endsWith("Controller")
                        ) {
                            method = superClass.methods.find { it.name.localName == methodName }
                            // Stop searching once found
                            if (method != null) break
                        }
                    }
                }

                // Register the found method
                method?.let {
                    registerHttpEndpoints(
                        method = it,
                        requestHandler = requestHandler,
                        path = "${basePath}/${methodName}",
                        httpMethod = httpMethod,
                    )
                }
            }
        }

        // The member variable defines specific actions on the controller, e.g.
        // `member = {'action': 'POST'}` means the "action" endpoint is accessible via a POST
        // request.
        val member = call.argumentEdges["member"]?.end as? InitializerListExpression
        member?.initializers?.filterIsInstance<KeyValueExpression>()?.forEach { keyValue ->
            val key = (keyValue.key as? Literal<*>)?.value?.toString()
            val httpMethod = (keyValue.value as? Literal<*>)?.value?.toString()
            val annotatedMethods =
                controller.methods.filter { method ->
                    method.annotations.any { it.name.localName == key }
                }
            // The endpoints are annotated with the action decorator (=`@wsgi.action(<key>)`)
            if (annotatedMethods.isNotEmpty()) {
                annotatedMethods.forEach { method ->
                    if (method.parameters.any { it.name.localName == "id" }) {
                        registerHttpEndpoints(
                            method = method,
                            requestHandler = requestHandler,
                            path = "${basePath}/{id}/action",
                            httpMethod = httpMethod,
                        )
                    } else {
                        registerHttpEndpoints(
                            method = method,
                            requestHandler = requestHandler,
                            path = "${basePath}/action",
                            httpMethod = httpMethod,
                        )
                    }
                }
            } else {
                // If the action is 'registered' but not with the annotation, then search by name
                controller.methods
                    .find { it.name.localName == key }
                    ?.let {
                        registerHttpEndpoints(
                            method = it,
                            requestHandler = requestHandler,
                            path = basePath,
                            httpMethod = httpMethod,
                        )
                    }
            }
        }
    }

    private fun getControllerFromCreateResource(call: CallExpression): RecordDeclaration? {
        val functionDeclaration = call.invokes.firstOrNull() as? FunctionDeclaration
        val returnValue =
            functionDeclaration?.returns?.firstOrNull()?.returnValue as? ConstructExpression
        val argument = returnValue?.arguments?.firstOrNull()
        val constructExpression = argument?.let { it as? ConstructExpression }
        val record = constructExpression?.instantiates as? RecordDeclaration

        return record
    }

    private fun registerEndpointsOfCrudMethods(
        methods: List<MethodDeclaration>,
        requestHandler: HttpRequestHandler,
        basePath: String,
    ) {
        val crudMethods = setOf("create", "update", "delete", "show", "index")
        methods
            .filter { it.name.localName in crudMethods }
            .forEach { method ->
                if (method.parameters.any { it.name.localName == "id" }) {
                    registerHttpEndpoints(
                        method = method,
                        requestHandler = requestHandler,
                        path = "${basePath}/{id}",
                    )
                } else {
                    registerHttpEndpoints(
                        method = method,
                        requestHandler = requestHandler,
                        path = basePath,
                    )
                }
            }
    }

    private fun handleResourceExtension(node: CallExpression, controller: RecordDeclaration) {
        val alias = extractEndpointPath(call = node, argumentIndex = 0)
        var path = "$apiVersionPath/$alias"

        // Check if the resource has a parent
        val parentDict = node.argumentEdges["parent"]?.end as? ConstructExpression
        if (parentDict != null) {
            val memberName = parentDict.arguments.getOrNull(0) as? Literal<*>
            val collectionName = parentDict.arguments.getOrNull(1) as? Literal<*>
            if (memberName != null && collectionName != null) {
                path = "$apiVersionPath/${collectionName.value}/{${memberName.value}}/$alias"
            }
        }

        val requestHandler = newHttpRequestHandler(underlyingNode = controller, basePath = path)
        registerEndpointsOfCrudMethods(
            methods = controller.methods,
            requestHandler = requestHandler,
            basePath = path,
        )
    }

    private fun registerHttpEndpoints(
        method: MethodDeclaration,
        requestHandler: HttpRequestHandler,
        path: String,
        httpMethod: String? = null,
    ) {
        val httpEndpoint =
            newHttpEndpoint(
                underlyingNode = method,
                httpMethod = httpMethod ?: method.name.localName,
                path = path,
                arguments = method.parameters,
            )
        requestHandler.endpoints.add(httpEndpoint)

        newRegisterHttpEndpoint(
            underlyingNode = method,
            concept = requestHandler,
            httpEndpoint = httpEndpoint,
        )
    }

    private fun extractEndpointPath(call: CallExpression, argumentIndex: Int): String? {
        val apiEndpoint =
            when (val endpoint = call.arguments.getOrNull(argumentIndex)) {
                is Literal<*> -> endpoint.value.toString()
                is BinaryOperator -> {
                    val path = (endpoint.lhs as Literal<*>).value
                    // TODO(lshala): Do we want the parameter project_id in the endpoint or not?
                    //  https://docs.openstack.org/api-ref/block-storage/v3/. Check how it is handed
                    //  over on the
                    //  client side. In cinder its the lib python-cinderclient. In ProjectMapper
                    //  resource()
                    //  (openstack/__init__.py) the project_id will already be retrieved from the
                    //  CONF

                    // replace for now
                    return path.toString().replace("%s/", "")
                }

                is MemberExpression -> {
                    val baseReference = endpoint.base as? Reference
                    val record = baseReference?.refersTo as? RecordDeclaration

                    val foundAlias =
                        record.statements.filterIsInstance<AssignExpression>().find { assign ->
                            val lhsRef = assign.lhs.firstOrNull() as? Reference
                            lhsRef?.name?.localName == endpoint.name.localName
                        }
                    return (foundAlias?.rhs?.firstOrNull() as? Literal<*>)?.value.toString()
                }

                else -> null
            }
        return apiEndpoint
    }
}
