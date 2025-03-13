/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.openstack.passes

import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.Forward
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.Node
import de.fraunhofer.aisec.cpg.graph.allEOGStarters
import de.fraunhofer.aisec.cpg.graph.component
import de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOperation
import de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption
import de.fraunhofer.aisec.cpg.graph.concepts.config.LoadConfiguration
import de.fraunhofer.aisec.cpg.graph.concepts.config.ReadConfigurationGroup
import de.fraunhofer.aisec.cpg.graph.concepts.config.ReadConfigurationOption
import de.fraunhofer.aisec.cpg.graph.concepts.config.RegisterConfigurationOption
import de.fraunhofer.aisec.cpg.graph.concepts.config.newConfiguration
import de.fraunhofer.aisec.cpg.graph.concepts.config.newConfigurationGroup
import de.fraunhofer.aisec.cpg.graph.concepts.config.newConfigurationOption
import de.fraunhofer.aisec.cpg.graph.concepts.config.newLoadConfiguration
import de.fraunhofer.aisec.cpg.graph.concepts.config.newRegisterConfigurationGroup
import de.fraunhofer.aisec.cpg.graph.concepts.config.newRegisterConfigurationOption
import de.fraunhofer.aisec.cpg.graph.edges.flows.CallingContextOut
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.fqn
import de.fraunhofer.aisec.cpg.graph.newLiteral
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberExpression
import de.fraunhofer.aisec.cpg.helpers.SubgraphWalker
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.concepts.config.ini.IniFileConfigurationSourcePass
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteBefore
import de.fraunhofer.aisec.cpg.processing.strategy.Strategy

/**
 * Translates configuration options from oslo.config to our configuration concept.
 *
 * Note: This pass needs to have the sources of oslo.config available, otherwise it will not be able
 * to resolve the types of the options.
 */
@DependsOn(PythonEntryPointPass::class)
@ExecuteBefore(IniFileConfigurationSourcePass::class)
class OsloConfigPass(ctx: TranslationContext) : ComponentPass(ctx) {

    lateinit var walker: SubgraphWalker.ScopedWalker

    override fun accept(c: Component) {
        // There seems to be some drivers for oslo.config, but we are not 100 % sure yet what they
        // are doing
        var driver =
            c.incomingInteractions.filterIsInstance<PythonEntryPoint>().singleOrNull {
                it.group == "oslo.config.driver"
            }
        if (driver != null) {
            log.warn("Found a driver for oslo.config: {}", driver)
        }

        ctx.currentComponent = c
        walker = SubgraphWalker.ScopedWalker(ctx.scopeManager)
        walker.strategy = Strategy::EOG_FORWARD
        walker.registerHandler { node -> handleNode(node) }

        val nodes = c.allEOGStarters.filter { it.prevEOGEdges.isEmpty() }

        for (node in nodes) {
            walker.iterate(node)
        }
    }

    private fun handleNode(node: Node) {
        when (node) {
            is ConstructExpression -> handleConstructExpression(node)
            is MemberCallExpression -> handleMemberCallExpression(node)
            is MemberExpression -> handleMemberExpression(node)
        }
    }

    /**
     * Translates a [MemberExpression] such as `conf.key_manager.backend` into a
     * [ReadConfigurationGroup] or [ReadConfigurationOption].
     */
    private fun handleMemberExpression(me: MemberExpression): List<ConfigurationOperation>? {
        // This is a MAJOR hack, since we do not have the type of the base yet :(
        if (
            me.base.name.localName != "conf" &&
                (me.base as? MemberExpression)?.base?.name?.localName != "conf"
        ) {
            return null
        }

        // We need to find out, whether our base is a configuration or a configuration group
        val paths =
            me.base.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                it is Configuration || it is ConfigurationGroup
            }
        return paths.fulfilled.mapNotNull {
            val last = it.lastOrNull()
            when (last) {
                is Configuration -> {
                    val group = last.groups.find { it.name.localName == me.name.localName }
                    if (group != null) {
                        val op = ReadConfigurationGroup(underlyingNode = me, group = group)

                        // Add an incoming DFG from the option group
                        me.prevDFGEdges.add(group)

                        op
                    } else {
                        null
                    }
                }
                is ConfigurationGroup -> {
                    val option = last.options.find { it.name.localName == me.name.localName }
                    if (option != null) {
                        val op = ReadConfigurationOption(underlyingNode = me, option = option)

                        // Add an incoming DFG from the option
                        me.prevDFGEdges.add(option)

                        // Add an incoming EOG from the option's default value (if specified)
                        option.value?.let { me.prevEOGEdges.add(it) }

                        op
                    } else {
                        null
                    }
                }
                else -> null
            }
        }
    }

    private fun handleConstructExpression(
        construct: ConstructExpression
    ): MutableList<ConfigurationOperation> {
        // Find constructor calls of oslo_config.cfg.ConfigOpts.
        if (construct.name.contains("ConfigOpts")) {
            handleConfigOptsConstruct(construct)
        }

        return mutableListOf()
    }

    /**
     * We follow the `oslo_config.cfg.ConfigOpts()` constructor calls back to the other
     * component(s), to find the "border" between oslo.config and the other component. Basically the
     * component is importing `cfg.CONF` from `oslo.config`, and we want to create one
     * [Configuration] node for each component that imports us and attach it to the CONF object.
     * Additionally, we create a [LoadConfiguration] operation, which is done internally by
     * `oslo.config.ConfigOpts.__call__`.
     *
     * This simulates that each "real" component is running on its own server and will invoke a new
     * configuration each when they import `cfg.CONF`.
     */
    private fun handleConfigOptsConstruct(
        expr: ConstructExpression
    ): MutableList<ConfigurationOperation> {
        val ops = mutableListOf<ConfigurationOperation>()

        val paths =
            expr.followDFGEdgesUntilHit(direction = Forward(GraphToFollow.DFG)) {
                // We are following until we "cross" into another component
                it.component != ctx.currentComponent
            }

        // Gather components that import this ConfigOpts object
        val components = paths.fulfilled.map { it.lastOrNull()?.component }.toSet()

        // And create one configuration for each component. We will attach it to the construct
        // expression, so if someone is interested in which configuration he is using, he can
        // just follow the DFG edges to the construct expression and look for a configuration that
        // matches the originating component
        for (component in components) {
            val conf =
                newConfiguration(underlyingNode = expr).also {
                    it.name = Name("conf", component?.name)
                }
            expr.prevDFGEdges.addContextSensitive(conf, callingContext = CallingContextOut(expr))

            val lit = newLiteral("${component?.name}.conf")
            newLoadConfiguration(underlyingNode = expr, concept = conf, fileExpression = lit).also {
                it.name = Name(lit.value.toString())
            }
        }

        return ops
    }

    private fun handleMemberCallExpression(
        call: MemberCallExpression
    ): List<ConfigurationOperation>? {
        // Should be oslo_config.cfg.ConfigOpts.register_opts but most of the time we don't have the
        // type of the base (yet)
        return if (call.name.localName == "register_opts") {
            handleRegisterOpts(call)
        } else {
            null
        }
    }

    val optNames =
        setOf(
            "oslo_config.cfg.StrOpt",
            "oslo_config.cfg.IntOpt",
            "oslo_config.cfg.BoolOpt",
            "oslo_config.cfg.ListOpt",
            "oslo_config.cfg.MultiStrOpt",
            "oslo_config.cfg.SubCommandOpt",
        )

    private fun handleRegisterOpts(
        registerOptsCall: MemberCallExpression
    ): List<ConfigurationOperation>? {
        // We need to find the matching configuration by following back the DFG of our base (the
        // "ConfigOpts" object) until we hit a configuration
        val confs =
            registerOptsCall.base
                ?.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                    it is Configuration
                }
                ?.fulfilled
                ?.mapNotNull { it.lastOrNull() as? Configuration }
                ?.toSet()
        return confs?.flatMap { conf -> handleRegisterOptsForConfiguration(registerOptsCall, conf) }
    }

    /**
     * Handles the `register_opts` call for a specific [Configuration]. This is done by following
     * the DFG of the first argument until we hit a call to one of the option constructors. For each
     * option constructor, we create a new [ConfigurationOption] and a
     * [RegisterConfigurationOption].
     */
    private fun handleRegisterOptsForConfiguration(
        registerOptsCall: MemberCallExpression,
        conf: Configuration,
    ): MutableList<ConfigurationOperation> {
        val ops = mutableListOf<ConfigurationOperation>()

        // First argument is list of options
        val firstArgument = registerOptsCall.arguments.getOrNull(0)
        val paths =
            firstArgument?.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                it is CallExpression && it.name.toString() in optNames
            }
        paths?.fulfilled?.forEach { path ->
            val optionCall = path.lastOrNull() as? CallExpression ?: return@forEach
            var group = registerGroupIfNotExists(registerOptsCall, conf, ops)

            val keyArgument = optionCall.arguments.getOrNull(0)
            if (keyArgument == null) {
                return@forEach
            }

            val defaultValueArgument =
                optionCall.argumentEdges.singleOrNull { it.name == "default" }?.end

            // Create a new ConfigurationOption for each option
            val option =
                newConfigurationOption(
                        underlyingNode = optionCall,
                        concept = group,
                        key = keyArgument,
                        value = defaultValueArgument,
                    )
                    .also { it.name = group.name.fqn(keyArgument.evaluate().toString()) }

            newRegisterConfigurationOption(
                underlyingNode = optionCall,
                concept = option,
                defaultValue = null,
            )
        }

        return ops
    }

    /**
     * The `register_opts` call implicitly creates a new group if it is not already present. We
     * therefore check, if it already has a register group operation attached to it
     */
    private fun registerGroupIfNotExists(
        registerOptsCall: CallExpression,
        conf: Configuration,
        ops: MutableList<ConfigurationOperation>,
    ): ConfigurationGroup {
        val groupArgument =
            registerOptsCall.arguments.getOrNull(1)
                ?: registerOptsCall.argumentEdges.singleOrNull { it.name == "group" }?.end

        val groupName =
            Name(
                if (groupArgument == null) {
                    "DEFAULT"
                } else {
                    groupArgument.evaluate().toString()
                }
            )

        var group = conf.groups.find { it.name == groupName }
        if (group == null) {
            // This is the first call we encounter that registers options to this group, so
            // we create it
            group =
                newConfigurationGroup(underlyingNode = registerOptsCall, concept = conf).also {
                    it.name = groupName
                }
            newRegisterConfigurationGroup(underlyingNode = registerOptsCall, concept = group)
        }

        return group
    }

    override fun cleanup() {
        // Nothing to do
    }
}
