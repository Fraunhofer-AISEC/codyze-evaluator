/*
 * This file is part of the OpenStack Checker
 */
package de.fraunhofer.aisec.codyze.passes.concepts.auth.openstack

import de.fraunhofer.aisec.codyze.analyze
import de.fraunhofer.aisec.codyze.graph.concepts.auth.Policy
import de.fraunhofer.aisec.codyze.graph.concepts.auth.PolicyRule
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.frontends.python.PythonLanguage
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import kotlin.io.path.Path
import kotlin.test.*

/**
 * This test suite contains tests for the [OsloPolicyPass], which analyzes OpenStack policy files
 * and extracts policies and their rules.
 */
class OsloPolicyPassTest {

    /**
     * Test case to see whether the [OsloPolicyPass] can correctly parse and identify policies and
     * their rules in the OpenStack project [Cinder]. The library [OsloPolicy] is also used.
     */
    @Test
    fun testPolicies() {
        val topLevel = Path("external")
        val result =
            analyze(listOf(), topLevel, true) {
                it.registerLanguage<PythonLanguage>()
                it.registerPass<OsloPolicyPass>()
                it.exclusionPatterns("tests", "drivers")
                it.includePath("external/oslo.policy")
                it.softwareComponents(
                    mutableMapOf(
                        Cinder.name to
                            listOf(
                                topLevel.resolve("cinder/cinder/policies").toFile(),
                                topLevel.resolve("cinder/cinder/policy.py").toFile(),
                            )
                    )
                )
                it.topLevels(mapOf(Cinder.name to topLevel.resolve("cinder").toFile()))
            }
        assertNotNull(result)

        val policies = result.conceptNodes.filterIsInstance<Policy>()
        assertNotNull(policies, "There should be Policies")

        val policyRules = result.conceptNodes.filterIsInstance<PolicyRule>()
        assertNotNull(policyRules, "There should be Policy rules")

        // Test one example rule
        val adminApiRule = policyRules.singleOrNull { it.name.localName == "admin_api" }
        assertNotNull(adminApiRule, "Should have found 'admin_api' rule")
        val roles = adminApiRule.roles
        assertNotNull(roles, "Should have roles for admin_api rule")
        assertEquals(2, roles.size)

        // Check for `role:admin` role
        val adminRole = roles.find { it.name == "role:admin" }
        assertNotNull(adminRole, "Should have role 'role:admin' in admin_api rule")

        // Check for `is_admin_project:True` condition
        val hasAdminProjectCondition =
            roles.any { role -> role.conditions.any { it.contains("is_admin_project:True") } }
        assertTrue(
            hasAdminProjectCondition,
            "Should have a role with condition 'is_admin_project:true'",
        )
    }
}
