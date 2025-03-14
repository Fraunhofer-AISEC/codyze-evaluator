/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes.http

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Annotation
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.assigns
import de.fraunhofer.aisec.cpg.graph.calls
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.MethodDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.RecordDeclaration
import de.fraunhofer.aisec.cpg.graph.edges.get
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.followEOGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.followPrevDFG
import de.fraunhofer.aisec.cpg.graph.methods
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
import de.fraunhofer.aisec.cpg.graph.types.recordDeclaration
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteLate
import de.fraunhofer.aisec.openstack.concepts.mapHttpMethod

@DependsOn(SymbolResolver::class)
@ExecuteLate
class HttpWsgiPass(ctx: TranslationContext) : ComponentPass(ctx) {
    val apiVersionPath = "/v3"

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
                    (it.name.localName == "ResourceExtension" ||
                            it.name.localName == "ControllerExtension") &&
                            it.name.parent?.localName == "extensions"
                }
            val resourceControllers = resourceCalls.map { it.second }
            handleExtensionRoutes(resourceExtensionCalls, resourceControllers)
        }
    }

    private val crudMethods = setOf("create", "update", "delete", "show", "index")

    /**
     * Handles the registration of controller extension routes, specifically for methods annotated
     * with `@action`.
     *
     * See
     * [OpenStack ExtensionsModule](https://docs.openstack.org/cinder/latest/contributor/api/cinder.api.extensions.html)
     */
    private fun handleControllerExtension(node: CallExpression, controller: RecordDeclaration) {
        val path =
            extractEndpointPath(call = node, argumentIndex = 1)
                ?: run {
                    // Hacky workaround: The CallExpression occurs inside a loop and the value we
                    // need here depends on a
                    // class variable. We extract the value by comparing the name of the
                    // MemberExpression with
                    // the FieldDeclaration.
                    val memberExpression = node.arguments.getOrNull(1) as? MemberExpression
                    val fieldDecl =
                        controller.fields.firstOrNull {
                            it.name.localName == memberExpression?.name?.localName
                        }
                    fieldDecl?.evaluate() as? String ?: ""
                }
        val basePath = buildPath(path)
        val requestHandler =
            newHttpRequestHandler(underlyingNode = controller, basePath = basePath, endpoints = mutableListOf())

        controller.methods
            .filter { it.hasAnnotation("action") }
            .forEach { method ->
                val member =
                    method.getAnnotation("action")?.members?.firstOrNull()?.value?.evaluate()
                            as? String
                val isCrudMethod = member in crudMethods
                val isAction = !isCrudMethod // If it's not a CRUD method, then it's an action
                val fullPath = buildPath(path = basePath, method = method, isAction = isAction)
                val httpMethod = if (isCrudMethod) member else "POST" // Default to POST for actions

                registerHttpEndpoints(
                    method = method,
                    requestHandler = requestHandler,
                    path = fullPath,
                    httpMethod = httpMethod,
                )
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
            val extensionControllers = getControllersFromResourceExtension(resourceExtensionCall)
            for (extensionController in extensionControllers) {
                // Check if controller is already registered
                if (
                    resourceControllers.any {
                        it.name.localName == extensionController.name.localName
                    }
                ) {
                    continue
                }
                when (resourceExtensionCall.name.localName) {
                    "ResourceExtension" -> {
                        handleResourceExtension(
                            node = resourceExtensionCall,
                            controller = extensionController,
                        )
                    }

                    "ControllerExtension" -> {
                        handleControllerExtension(
                            node = resourceExtensionCall,
                            controller = extensionController,
                        )
                    }
                }
            }
        }
    }

    /**
     * Second argument of
     * [`ResourceExtension`](https://docs.openstack.org/cinder/latest/contributor/api/cinder.api.extensions.html#cinder.api.extensions.ResourceExtension)
     * is always the referenced Controller
     */
    private fun getControllersFromResourceExtension(call: CallExpression): List<RecordDeclaration> {
        val controllerArg =
            when (call.name.localName) {
                "ControllerExtension" -> call.arguments.getOrNull(2)
                "ResourceExtension" -> call.arguments.getOrNull(1)
                else -> null
            }

        return when (controllerArg) {
            is Reference -> {
                val construct =
                    controllerArg.followPrevDFG { it is ConstructExpression }?.lastOrNull()
                            as? ConstructExpression

                if (construct != null) {
                    listOfNotNull(construct.instantiates as? RecordDeclaration)
                } else {
                    val initializerList =
                        controllerArg
                            .followEOGEdgesUntilHit(direction = Backward(GraphToFollow.EOG)) {
                                it is InitializerListExpression
                            }
                            .fulfilled
                            .firstOrNull()
                            ?.lastOrNull() as? InitializerListExpression

                    initializerList?.initializers?.filterIsInstance<Reference>()?.mapNotNull {
                        it.followPrevDFG { node -> node is RecordDeclaration }?.lastOrNull()
                                as? RecordDeclaration
                    } ?: emptyList()
                }
            }

            is ConstructExpression ->
                listOfNotNull(controllerArg.instantiates as? RecordDeclaration)

            else -> emptyList()
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
        val requestHandler =
            newHttpRequestHandler(
                underlyingNode = controller,
                basePath = basePath,
                endpoints = mutableListOf(),
            )

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
        val initializerList =
            conditions
                ?.initializers
                ?.filterIsInstance<KeyValueExpression>()
                ?.firstOrNull { it.key.evaluate() == "method" }
                ?.value as? InitializerListExpression
        val httpMethod = initializerList?.initializers?.singleOrNull()?.evaluate() as? String

        // Extract the name of the action which is usually also the name of the method itself, e.g.
        // `action='update_all'`.
        val methodName = call.argumentEdges["action"]?.end?.evaluate() as? String
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
            val annotatedMethods = controller.methods.filter { it.hasAnnotation(methodName) }
            annotatedMethods.forEach { method ->
                val endpointWithId = endpoint.contains("id", ignoreCase = true)
                val methodWithId = method.hasIdParameter()

                if (endpointWithId && methodWithId || !endpointWithId && !methodWithId) {
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
                    it.argumentEdges["member_name"]?.end.let { arg -> arg?.evaluate() as? String }
                val collectionName =
                    it.argumentEdges["collection_name"]?.end.let { arg ->
                        arg?.evaluate() as? String
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
            val methodName = keyValue.key.evaluate() as? String
            val httpMethod = keyValue.value.evaluate() as? String

            if (methodName != null && httpMethod != null) {
                var method = findMethodInControllerAndSuperClasses(controller, methodName)

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
            val key = keyValue.key.evaluate() as? String
            val httpMethod = keyValue.value.evaluate() as? String

            if (key != null && httpMethod != null) {
                // The endpoints are annotated with the action decorator (=`@wsgi.action(<key>)`)
                val annotatedMethods = controller.methods.filter { it.hasAnnotation(key) }
                if (annotatedMethods.isNotEmpty()) {
                    annotatedMethods.forEach { method ->
                        val path = buildPath(path = basePath, method = method, isAction = true)
                        registerHttpEndpoints(
                            method = method,
                            requestHandler = requestHandler,
                            path = path,
                            httpMethod = httpMethod,
                        )
                    }
                } else {
                    // If the action is 'registered' but not with the annotation, then search by
                    // name
                    var method = findMethodInControllerAndSuperClasses(controller, methodName = key)

                    // If method is found, register the endpoint
                    method?.let {
                        val path =
                            buildPath(path = basePath, method = it, methodName = it.name.localName)
                        registerHttpEndpoints(
                            method = it,
                            requestHandler = requestHandler,
                            path = path,
                            httpMethod = httpMethod,
                        )
                    }
                }
            }
        }
    }

    /** Tries to find a method in the current controller or its superclasses. */
    fun findMethodInControllerAndSuperClasses(
        controller: RecordDeclaration,
        methodName: String,
    ): MethodDeclaration? {
        // Search in the current controller
        var method = controller.methods.find { it.name.localName == methodName }

        // If not found, check in the superclasses
        if (method == null) {
            for (superClass in controller.superClasses.mapNotNull { it.recordDeclaration }) {
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
        return method
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
        methods
            .filter { it.name.localName in crudMethods }
            .forEach { method ->
                val path = buildPath(path = basePath, method = method)
                registerHttpEndpoints(method = method, requestHandler = requestHandler, path = path)
            }
    }

    private fun handleResourceExtension(node: CallExpression, controller: RecordDeclaration) {
        val alias = extractEndpointPath(call = node, argumentIndex = 0)
        var path = "$apiVersionPath/$alias"

        // Check if the resource has a parent
        val parentDict = node.argumentEdges["parent"]?.end as? ConstructExpression
        if (parentDict != null) {
            val memberName =
                parentDict.arguments.getOrNull(0).let { arg -> arg?.evaluate() as? String }
            val collectionName =
                parentDict.arguments.getOrNull(1).let { arg -> arg?.evaluate() as? String }
            if (memberName != null && collectionName != null) {
                path = "$apiVersionPath/${collectionName}/{${memberName}}/$alias"
            }
        }

        val requestHandler =
            newHttpRequestHandler(
                underlyingNode = controller,
                basePath = path,
                endpoints = mutableListOf(),
            )
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
                httpMethod = mapHttpMethod(httpMethod ?: method.name.localName),
                path = path,
                arguments = method.parameters,
                authentication = null,
            )
                .apply {
                    this.nextDFG += method
                    this.prevDFG += method
                }
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
                is Literal<*> -> endpoint.evaluate() as? String
                is BinaryOperator -> {
                    val path = endpoint.lhs.evaluate() as? String
                    // TODO(lshala): Do we want the parameter project_id in the endpoint or not?
                    //  https://docs.openstack.org/api-ref/block-storage/v3/. Check how it is handed
                    //  over on the client side. In cinder its the lib python-cinderclient. In
                    //  ProjectMapper.resource() (openstack/__init__.py), the project_id will already
                    //  be retrieved from the CONF.

                    // replace for now
                    return path.toString().replace("%s/", "")
                }

                is MemberExpression -> {
                    val baseReference = endpoint.base as? Reference
                    val record = baseReference?.refersTo as? RecordDeclaration
                    if (record != null) {
                        val alias =
                            record.statements.filterIsInstance<AssignExpression>().find { assign ->
                                val lhsRef = assign.lhs.firstOrNull() as? Reference
                                lhsRef?.name?.localName == endpoint.name.localName
                            }
                        return alias?.rhs?.firstOrNull()?.evaluate() as? String
                    } else {
                        null
                    }
                }

                else -> null
            }
        return apiEndpoint
    }

    private fun buildPath(
        path: String?,
        method: MethodDeclaration? = null,
        isAction: Boolean = false,
        methodName: String? = null,
    ): String {
        var fullPath = path?.takeIf { it.startsWith(apiVersionPath) } ?: "$apiVersionPath/$path"
        if (method != null && method.hasIdParameter()) {
            fullPath += "/{id}"
        }
        if (isAction) {
            fullPath += "/action"
        }
        if (methodName != null) {
            fullPath += "/$methodName"
        }
        return fullPath
    }

    override fun cleanup() {
        // Nothing to do here
    }
}

fun MethodDeclaration.getAnnotation(annotationName: String): Annotation? {
    return annotations.firstOrNull { it.name.localName == annotationName }
}

fun MethodDeclaration.hasIdParameter(): Boolean {
    return parameters.any { it.name.localName.equals("id", ignoreCase = true) }
}

fun MethodDeclaration.hasAnnotation(annotationName: String): Boolean {
    return annotations.any { it.name.localName == annotationName }
}
