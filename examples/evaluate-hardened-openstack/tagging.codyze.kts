/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.GetSecret
import de.fraunhofer.aisec.cpg.graph.concepts.crypto.encryption.Secret
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression

project {
    tagging {
        tag {
            // Identifies the call to `retrieve_plugin.get_secret()` in barbican because this is
            // where the key is read e.g. from an HSM or something else (depending on the
            // configuration).
            each<MemberCallExpression> {
                    it.name.localName == "get_secret" &&
                        it.base?.name?.localName == "retrieve_plugin"
                }
                .withMultiple {
                    val secret = Secret()
                    val getSecret = GetSecret(concept = secret).apply { this.nextDFG += node }
                    listOf(secret, getSecret)
                }

            // Use a predefined tagging profile for Keystone middleware authentication.
            tagKeystoneMiddlewareAuthentication()

            // Use a predefined tagging profile for domain scope.
            tagDomainScope()

            // Use a predefined tagging profile for database access.
            tagDatabaseAccess()

            // Use a predefined tagging profile for secret definitions in OpenStack.
            decryptedCertToSecret()
            getSecretPluginCall()
        }
    }
}
