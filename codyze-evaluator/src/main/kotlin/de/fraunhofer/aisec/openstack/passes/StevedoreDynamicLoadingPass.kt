/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Forward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DynamicLoading
import de.fraunhofer.aisec.cpg.graph.concepts.memory.DynamicLoadingOperation
import de.fraunhofer.aisec.cpg.graph.concepts.memory.LoadSymbol
import de.fraunhofer.aisec.cpg.graph.concepts.memory.newDynamicLoading
import de.fraunhofer.aisec.cpg.graph.concepts.memory.newLoadSymbol
import de.fraunhofer.aisec.cpg.graph.declarations.ConstructorDeclaration
import de.fraunhofer.aisec.cpg.graph.declarations.TranslationUnitDeclaration
import de.fraunhofer.aisec.cpg.graph.edges.flows.CallingContextOut
import de.fraunhofer.aisec.cpg.graph.edges.flows.FullDataflowGranularity
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.implicit
import de.fraunhofer.aisec.cpg.graph.newConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.InitializerListExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.graph.types.FunctionType.Companion.computeType
import de.fraunhofer.aisec.cpg.graph.types.Type
import de.fraunhofer.aisec.cpg.helpers.Util.debugWithFileLocation
import de.fraunhofer.aisec.cpg.helpers.Util.warnWithFileLocation
import de.fraunhofer.aisec.cpg.passes.Pass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.concepts.ConceptPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ProvideConfigPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.concepts.config.python.stringValues
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.markDirty

/**
 * Translates usages of `stevedore.driver.DriverManager` into dynamic loading concepts.
 *
 * Note: This requires the source code (or typings) of
 * [stevedore](https://github.com/openstack/stevedore) to be present in order get have correct type
 * information.
 */
@DependsOn(PythonEntryPointPass::class)
@DependsOn(IniFileConfigurationSourcePass::class)
@DependsOn(OsloConfigPass::class)
@DependsOn(ProvideConfigPass::class)
class StevedoreDynamicLoadingPass(ctx: TranslationContext) : ConceptPass(ctx) {

    override fun handleNode(node: Node, tu: TranslationUnitDeclaration) {
        when (node) {
            is MemberExpression -> handleMemberExpression(node)
        }
    }

    private fun handleMemberExpression(me: MemberExpression) {
        if (me.name.toString() == "stevedore.driver.DriverManager.driver") {
            handleDriverAccess(me)
        }
    }

    /**
     * Translates a `stevedore.driver.DriverManager.driver` property access into a [LoadSymbol]
     * operation.
     *
     * We need to look at the corresponding `stevedore.driver.DriverManager(entry_point, value,
     * invoke_args=None)` constructor call to retrieve the necessary information.
     *
     * We instantiate a new variable with a [ConstructExpression] based on the record that is chosen
     * by the driver manager:
     * - The first argument is the key of the entry points we need to look at (see
     *   [PythonEntryPoint.group]). This will give us a list of entries points that we can choose
     *   from.
     * - The second argument is the value we need to look at. The entry point should contain a
     *   [ConstructorDeclaration] we can invoke. This is most likely coming from a configuration.
     *   Ideally when we invoke [OsloConfigPass] and [IniFileConfigurationPass] beforehand, there
     *   should be already DFG edges linking the code with the configuration, so that we can just
     *   "evaluate" the value.
     * - Finally, a named argument `invoke_args` contains an array of expressions that are being
     *   forwarded to the constructor.
     */
    private fun handleDriverAccess(me: MemberExpression): List<DynamicLoadingOperation<*>> {
        val paths =
            me.base.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                it is ConstructExpression
            }
        return paths.fulfilled
            .mapNotNull { it.nodes.last() as? ConstructExpression }
            .flatMap {
                return handleStevedoreDriverManager(it, me)
            }
    }

    /**
     * Creates a new [LoadSymbol] operation based on the information of a
     * `stevedore.driver.DriverManager(entry_point, value, invoke_args=None)` constructor call and
     * the driver access. We associate the [DynamicLoading] concept to the constructor call and the
     * [LoadSymbol] to the driver access.
     *
     * We instantiate a new variable with a [ConstructExpression] based on the record that is chosen
     * by the driver manager:
     * - The first argument is the key of the entry points we need to look at (see
     *   [PythonEntryPoint.group]). This will give us a list of entries points that we can choose
     *   from.
     * - The second argument is the value we need to look at. The entry point should contain a
     *   [ConstructorDeclaration] we can invoke. This is most likely coming from a configuration.
     *   Ideally when we invoke [OsloConfigPass] and [IniFileConfigurationPass] beforehand, there
     *   should be already DFG edges linking the code with the configuration, so that we can just
     *   "evaluate" the value.
     * - Finally, a named argument `invoke_args` contains an array of expressions that are being
     *   forwarded to the constructor.
     */
    private fun handleStevedoreDriverManager(
        constructDriver: CallExpression,
        accessDriver: MemberExpression,
    ): MutableList<DynamicLoadingOperation<*>> {
        val ops = mutableListOf<DynamicLoadingOperation<*>>()
        val possibleTypes = mutableListOf<Type>()

        // Create a new dynamic loading concept and associate it to the driver creation
        val concept = newDynamicLoading(constructDriver, connect = true)

        assume(
            constructDriver,
            component = "stevedore",
            additionalComponents = listOf("setuptools"),
        ) {
            "We assume that stevedore.driver.DriverManager looks up a setupools entry point group of the caller" +
                " based on the first argument and loads the corresponding entry point based on the second."
        }

        // This is most likely just a literal string, so we just use the simple evaluator
        val entryPointGroup = constructDriver.arguments.getOrNull(0)?.evaluate()

        // This could potentially refer to multiple configurations, so we use the multi value
        // evaluator. This could then result in multiple load operations
        val entryPointValues = constructDriver.arguments.getOrNull(1)?.stringValues ?: listOf()
        for (entryPointValue in entryPointValues) {
            val entryPoints =
                constructDriver.component
                    ?.incomingInteractions
                    ?.filterIsInstance<PythonEntryPoint>()
            val impl =
                entryPoints
                    ?.firstOrNull {
                        it.group == entryPointGroup && it.name.localName == entryPointValue
                    }
                    ?.underlyingNode as? ConstructorDeclaration

            if (impl != null) {
                val constructExpr = newConstructExpression(impl.name.toString()).implicit()
                constructExpr.constructor = impl

                // Retrieve list of arguments and associate them to the construct expression
                val args =
                    constructDriver.argumentEdges.singleOrNull { it.name == "invoke_args" }?.end
                        as? InitializerListExpression
                if (args != null) {
                    constructExpr.arguments.addAll(args.initializers)
                }

                possibleTypes += constructExpr.type

                val load =
                    newLoadSymbol<ConstructorDeclaration>(
                        accessDriver,
                        concept = concept,
                        what = impl,
                        loader = null,
                        os = null,
                        connect = true,
                    )

                accessDriver.prevDFGEdges.addContextSensitive(
                    node = constructExpr,
                    granularity = FullDataflowGranularity,
                    callingContext = CallingContextOut(constructDriver),
                )

                // We have new information that is relevant for the symbol resolver, trigger its
                // execution again
                accessDriver.markDirty<SymbolResolver>()

                ops += load
            } else {
                warnWithFileLocation(
                    constructDriver,
                    log,
                    "Could not find entry point {} in group {}",
                    entryPointValue,
                    entryPointGroup,
                )
            }
        }

        // We can make our life easier if we only have one particular type -> assign it to the
        // driver access
        possibleTypes.singleOrNull()?.let {
            accessDriver.type = it

            // If we see that the driver flows to the current function declaration, also set the
            // type. This is a little bit of a hack, but otherwise the types won't propagate
            // properly
            val current = scopeManager.currentFunction
            if (
                current != null &&
                    accessDriver
                        .followDFGEdgesUntilHit(
                            findAllPossiblePaths = false,
                            direction = Forward(GraphToFollow.DFG),
                        ) {
                            it == current
                        }
                        .fulfilled
                        .isNotEmpty()
            ) {
                current.returnTypes = listOf(it)
                current.type = computeType(current)
                debugWithFileLocation(
                    current,
                    log,
                    "Adjusting return type of {} to {}",
                    current,
                    it,
                )
            }
        }

        return ops
    }

    override fun cleanup() {
        // nothing to do
    }
}

private fun Pass<*>.assume(
    expression: CallExpression,
    component: String,
    additionalComponents: List<String>,
    function: () -> String,
) {
    // Nothing to do yet
}
