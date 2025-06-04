/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.concepts.auth.Policy
import de.fraunhofer.aisec.codyze.concepts.auth.PolicyRule
import de.fraunhofer.aisec.codyze.concepts.auth.Role
import de.fraunhofer.aisec.codyze.concepts.auth.newPolicy
import de.fraunhofer.aisec.codyze.concepts.auth.newPolicyRule
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.TranslationContext
import de.fraunhofer.aisec.cpg.graph.Backward
import de.fraunhofer.aisec.cpg.graph.Component
import de.fraunhofer.aisec.cpg.graph.GraphToFollow
import de.fraunhofer.aisec.cpg.graph.Name
import de.fraunhofer.aisec.cpg.graph.evaluate
import de.fraunhofer.aisec.cpg.graph.followDFGEdgesUntilHit
import de.fraunhofer.aisec.cpg.graph.mcalls
import de.fraunhofer.aisec.cpg.graph.statements.expressions.ConstructExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.InitializerListExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import de.fraunhofer.aisec.cpg.graph.statements.expressions.Reference
import de.fraunhofer.aisec.cpg.helpers.Util.warnWithFileLocation
import de.fraunhofer.aisec.cpg.passes.ComponentPass
import de.fraunhofer.aisec.cpg.passes.SymbolResolver
import de.fraunhofer.aisec.cpg.passes.configuration.DependsOn
import de.fraunhofer.aisec.cpg.passes.configuration.ExecuteBefore

/** A pass to register policies for OpenStack components using the [OsloPolicy] library. */
@DependsOn(SymbolResolver::class)
@DependsOn(SetOsloPolicyEnforcerTypePass::class)
@ExecuteBefore(AuthorizationPass::class)
class OsloPolicyPass(ctx: TranslationContext) : ComponentPass(ctx) {
    override fun accept(p0: Component) {
        /** The entry point of `oslo.policy` to register default policies */
        val registerDefaults = p0.mcalls.singleOrNull { it.name.localName == "register_defaults" }
        if (registerDefaults != null) {
            val policies = handleRegisterDefaultRules(registerDefaults)
            handleRules(policies = policies)
        }
    }

    /**
     * The `register_defaults` method gets a list of policy definitions provided. We follow back the
     * data flow to find them and create a [Policy] for each entry.
     */
    private fun handleRegisterDefaultRules(registerDefaults: MemberCallExpression): List<Policy> {
        val policies: MutableList<Policy> = mutableListOf()
        val paths =
            registerDefaults.followDFGEdgesUntilHit(direction = Backward(GraphToFollow.DFG)) {
                it is InitializerListExpression
            }
        paths.fulfilled.mapNotNull {
            val initializerListExpr = it.nodes.lastOrNull() as? InitializerListExpression
            initializerListExpr?.initializers?.forEach { initializer ->
                // Expect a `DocumentedRuleDefault` or `RuleDefault`
                val ruleConstruct = initializer as? ConstructExpression ?: return@forEach
                val rule = ruleConstruct.arguments.firstOrNull() ?: return@forEach
                policies +=
                    newPolicy(underlyingNode = ruleConstruct, connect = true).also {
                        it.name = Name(rule.evaluate().toString())
                        it.prevDFG += rule
                    }
            }
        }
        return policies
    }

    /**
     * This method goes through the policies to check their 'check strings'. If a check string
     * refers to another rule (e.g., "rule:<name>"), it finds the matching rule, extracts roles and
     * conditions and creates a [PolicyRule] for the policy.
     */
    private fun handleRules(policies: List<Policy>) {
        for (policy in policies) {
            val ruleConstruct = policy.underlyingNode as? ConstructExpression ?: continue
            val ruleCheckString =
                ruleConstruct.argumentEdges.firstOrNull { it.name == "check_str" }?.end
                    ?: ruleConstruct.arguments.getOrNull(1)
            if (ruleCheckString != null) {
                when (ruleCheckString) {
                    is Reference -> {
                        val ruleValue = ruleCheckString.evaluate() as? String
                        if (ruleValue?.startsWith("rule:") == true) {
                            val ruleName = ruleValue.substringAfter("rule:")
                            val matchingPolicy = policies.findMatchingPolicy(ruleName) ?: return
                            val construct =
                                matchingPolicy.underlyingNode as? ConstructExpression ?: return
                            val checkStrValue =
                                matchingPolicy.getCheckStrValue()
                                    ?: run {
                                        warnWithFileLocation(
                                            ruleCheckString,
                                            log,
                                            "Could not evaluate the check string",
                                        )
                                        return
                                    }

                            val roles = extractRoleInfos(checkStr = checkStrValue)
                            newPolicyRule(
                                    underlyingNode = construct,
                                    concept = policy,
                                    roles = roles,
                                    connect = true,
                                )
                                .apply { this.name = Name(ruleName) }
                        }
                    }
                }
            }
        }
    }

    /** Finds a policy matching the given rule name. */
    private fun List<Policy>.findMatchingPolicy(ruleName: String): Policy? {
        return this.find { policy ->
            val construct = policy.underlyingNode as? ConstructExpression ?: return@find false
            if (construct.name.localName != "RuleDefault") {
                return@find false
            }
            val defaultName =
                construct.arguments.getOrNull(0)?.evaluate() as? String ?: return@find false
            defaultName == ruleName
        }
    }

    /** Extracts the check string value from a policy. */
    private fun Policy.getCheckStrValue(): String? {
        val construct = underlyingNode as? ConstructExpression ?: return null
        // Second argument in `RuleDefault` contains the check string
        return construct.arguments.getOrNull(1)?.evaluate() as? String
    }

    /**
     * Extracts [Role]s from a check string.
     *
     * The check string is parsed to identify roles (starting with "role:") and their associated
     * conditions. Roles are split by "or" and "and" operators, with conditions being
     * [pre-defined rules](https://docs.openstack.org/cinder/2025.1/configuration/block-storage/policy-config-HOWTO.html).
     *
     * @param checkStr The check string (e.g., "role:admin or (role:reader and
     *   project_id:%(project_id)s)")
     */
    fun extractRoleInfos(checkStr: String): Set<Role> {
        // Remove outer parentheses and split the "or"s
        val orParts = checkStr.replace(Regex("[()]+"), "").split(" or ")
        val roleInfos = mutableSetOf<Role>()

        for (part in orParts) {
            // Split "and"s
            val andParts = part.trim().split(" and ")
            // Identify roles (starting with "role:")
            val actualRoles = andParts.filter { it.trim().startsWith("role:") }
            // Collect conditions (all non-role parts)
            val conditions =
                andParts.filter { !it.trim().startsWith("role:") }.map { it.trim() }.toSet()

            if (actualRoles.isNotEmpty()) {
                // For each actual role (starting with "role:...")
                actualRoles.forEach { role ->
                    roleInfos.add(Role(name = role, conditions = conditions))
                }
            } else {
                // If no role is found, this typically is a pre-defined policy rule
                andParts.forEach { part ->
                    roleInfos.add(Role(name = part, conditions = emptySet()))
                }
            }
        }

        return roleInfos
    }

    override fun cleanup() {
        // Nothing to do
    }
}
