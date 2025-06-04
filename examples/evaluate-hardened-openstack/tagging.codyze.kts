/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.statements.expressions.CallExpression

project {
    tagging {
        tag {
            each<CallExpression> { it.name.contains("encrypt") }.with { Secret() }

            // Use a predefined tagging profile for Keystone middleware authentication.
            tagKeystoneMiddlewareAuthentication()

            // Use a predefined tagging profile for domain scope.
            tagDomainScope()

            // Use a predefined tagging profile for database access.
            tagDatabaseAccess()
        }
    }
}
