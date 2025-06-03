/*
 * This file is part of the OpenStack Checker
 */
package auth

import analyze
import de.fraunhofer.aisec.codyze.concepts.auth.Policy
import de.fraunhofer.aisec.codyze.concepts.auth.PolicyRule
import de.fraunhofer.aisec.cpg.graph.conceptNodes
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OsloPolicyPassTest {
    @Test
    fun testPolicies() {
        val topLevel = Path("external")
        val result = analyze(listOf(), topLevel, true)
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
