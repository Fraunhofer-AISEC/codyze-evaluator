/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.queries.authorization.*
import de.fraunhofer.aisec.codyze.queries.encryption.*
import de.fraunhofer.aisec.codyze.queries.file.*
import de.fraunhofer.aisec.codyze.queries.keymanagement.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import example.queries.keystoneAuthStrategyConfigured

include {
    Tagging from "tagging.codyze.kts"
    ManualAssessment from "assessment.codyze.kts"
}

project {
    name = "Evaluation Project for Hardened OpenStack"

    /**
     * This block describes the Target of Evaluation (ToE). It is used to define the properties of
     * the ToE (e.g., its name), its architecture, and the requirements that need to be checked.
     *
     * This specific ToE represents a version of OpenStack that is hardened with a specific
     * configuration to meet security requirements.
     */
    toe {
        name = "Hardened OpenStack"
        version = "2024.2"

        /**
         * This block describes the general architecture of the ToE, including its module.
         *
         * Each module will be loaded into the graph.
         */
        architecture {
            modules {
                /**
                 * [Cinder] is the OpenStack block storage service that provides persistent block
                 * storage to instances. It supports various backends and allows users to manage
                 * volumes.
                 */
                module("cinder") {
                    directory = "toe/modules/cinder"
                    include("cinder")
                    exclude("tests", "drivers", "libvirt")
                }

                /**
                 * [Barbican] is the OpenStack key manager service that provides secure storage and
                 * management of secrets, such as encryption keys, passwords, and certificates.
                 */
                module("barbican") {
                    directory = "toe/modules/barbican"
                    include("barbican")
                    exclude("tests")
                }

                /**
                 * [Magnum] is the OpenStack container orchestration service that provides container
                 * management capabilities.
                 */
                module("magnum") {
                    directory = "toe/modules/magnum"
                    include("magnum")
                    exclude("tests", "drivers")
                }

                /**
                 * [Castellan] is a library for managing secrets in OpenStack, providing abstraction
                 * over various key management services, such as Barbican.
                 */
                module("castellan") {
                    directory = "toe/libraries/castellan"
                    include("castellan")
                    exclude("tests")
                }

                /**
                 * The "conf" module contains specific OpenStack configuration files and settings
                 * that are used for the specific OpenStack deployment.
                 */
                module("conf") {
                    directory = "toe/conf"
                    includeAll()
                }

                /** [OsloConfig] is a library for managing configuration files in OpenStack. */
                module("oslo.config") {
                    directory = "toe/libraries/oslo.config"
                    include("oslo_config")
                    exclude("tests")
                }

                /**
                 * [KeystoneMiddleware] is a library that provides middleware components for
                 * OpenStack Keystone, the identity service.
                 */
                module("keystonemiddleware") {
                    directory = "toe/libraries/keystonemiddleware"
                    include("keystonemiddleware")
                    exclude("tests", "migrations")
                }
            }
        }

        /**
         * This block describes the requirements that need to be checked. Requirements can either be
         * automatically checked by a query or by manual inspection.
         */
        requirements {
            requirement {
                name = "Check Security Target Description for Consistency"

                fulfilledBy { manualAssessmentOf("SEC-TARGET") }
            }

            /** This category contains requirements related to the ecosystem of OpenStack. */
            category("Eco-System") {
                /**
                 * Identify and assess open and unresolved vulnerabilities in the project's codebase
                 * or dependencies, using services like OSV, to ensure important fixes are
                 * integrated.
                 */
                requirement {
                    name = "No Known Vulnerabilities"

                    fulfilledBy { manualAssessmentOf("Dependencies") }
                }

                /**
                 * Assure that timely updates of dependencies are continuously integrated, using
                 * tools like proposal bots. Verify active development and maintenance activities,
                 * ensuring adherence to security policies and having proper licenses.
                 */
                requirement { name = "Continuous Maintenance" }

                /**
                 * Review adherence to best practices for open-source projects, including
                 * key-hardening headers and dynamic analysis tools for major releases. Check the
                 * project's OSSF best practices badge.
                 */
                requirement { name = "CI/CD Best Practices" }

                /**
                 * Verify the execution of CI tests and mandatory and correct integration of tools
                 * like Zuul before code merges. Also look into the usage of fuzzing, SAST tools,
                 * and evaluate the testing interface consistency across projects.
                 */
                requirement { name = "Continuous Testing" }

                /**
                 * Ensure that CI/CD security settings are properly configured, including Gerrit
                 * settings, branch protection, token permissions, and the evaluation of dangerous
                 * workflows to prevent unauthorized code changes.
                 */
                requirement {
                    name = "CI/CD Security"

                    fulfilledBy { manualAssessmentOf("Branch-Protection") }
                }

                /**
                 * Ensure that code changes undergo human reviews, assessing contributor diversity,
                 * and reviewing metrics related to code contributions, such as contributor
                 * frequency and code review participation.
                 */
                requirement {
                    name = "Code Contributions and Reviews"

                    fulfilledBy {
                        manualAssessmentOf("Release-Reviewers-Nova") and
                            manualAssessmentOf("Contributor-Diversity-Nova")
                    }
                }

                /**
                 * Check for binary artifacts in repositories, assess dependency pinning, evaluate
                 * packaging and signed releases to mitigate build risks, ensuring reproducibility
                 * and security of artifacts.
                 */
                requirement { name = "Build Risks" }
            }

            /** This describes generic security requirements for all OpenStack components. */
            category("General") {
                name = "General Security Requirements"

                /**
                 * See
                 * [Guideline on Restrictive File Permissions](https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html).
                 */
                requirement {
                    name = "Apply Restrictive File Permissions"

                    // This query checks if restrictive file permissions are applied when writing
                    // files. But only if the file is written from a secret.
                    fulfilledBy {
                        restrictiveFilePermissionsAreAppliedWhenWriting(
                            select = OnlyWritesFromASecret
                        )
                    }
                }

                /**
                 * Ensure that temporary files are always deleted after use. This reduces the
                 * timeframe where data may be accessible to other parties.
                 */
                requirement {
                    name = "Delete Temporary Files After Use"

                    // This query checks if restrictive file permissions are applied when writing
                    // files. But only if the file is written from a secret.
                    fulfilledBy { temporaryFilesAreAlwaysDeleted() }
                }

                /** Secret data should be deleted from memory, ideally right after usage. */
                requirement {
                    name = "Delete Secrets after Usage"

                    // We can use method references when we do not need to pass any parameters.
                    fulfilledBy(::secretsAreDeletedAfterUsage)
                }

                /**
                 * Secret data must not be logged, i.e., they must not flow into a
                 * logging-statement.
                 */
                requirement {
                    name = "Secrets Must not be Logged"

                    fulfilledBy(::noLoggingOfSecrets)
                }
            }

            /**
             * Ensure that the OpenStack deployment supports Bring Your Own Key (BYOK) for disk
             * encryption, allowing users to manage their own encryption keys.
             */
            category("BYOK") {
                name = "Bring Your Own Key (BYOK)"

                /**
                 * The block device encryption algorithm must be state of the art, e.g., refer to a
                 * TR.
                 */
                requirement {
                    name = "State-of-the-Art Disk Encryption Algorithm"

                    fulfilledBy {
                        (stateOfTheArtEncryptionIsUsed() and minimalKeyLengthIsEnforced()) or
                            manualAssessmentOf("Careful-Crypto-Analysis")
                    }
                }

                /**
                 * Given a disk encryption operation, the key used in the operation must be provided
                 * by a secure key provider, leaked through other output and deleted after use.
                 *
                 * This is a more complex requirement that checks multiple aspects of key
                 * management.
                 */
                requirement {
                    name = "Key for Disk Encryption is Kept Secure"

                    fulfilledBy {
                        val notLeakedAndReachable =
                            keyNotLeakedThroughOutput(
                                isLeakyOutput = Node::dataLeavesOpenStackComponent
                            ) and
                                keyOnlyReachableThroughSecureKeyProvider(
                                    isSecureKeyProvider = HttpEndpoint::isSecureOpenStackKeyProvider
                                )

                        notLeakedAndReachable and keyIsDeletedFromMemoryAfterUse()
                    }
                }

                /** The key must be protected when in transit. */
                requirement {
                    name = "Transport Encryption of Key"

                    fulfilledBy { transportEncryptionForKeys() }
                }

                /**
                 * The key must only be accessible by a valid user and through the REST API of
                 * [Barbican].
                 */
                requirement {
                    name = "Key Accessible Only By Valid User"

                    fulfilledBy { keyOnyAccessibleByAuthenticatedEndpoint() }
                }
            }

            /**
             * This category contains requirements related to multi-tenancy in OpenStack, ensuring
             * that the system is designed to support multiple tenants securely and efficiently.
             */
            category("Multi-Tenancy") {
                name = "Multi-Tenancy"

                /** All authentication operations must use Keystone as the identity service. */
                requirement {
                    name = "Use Keystone for authentication"

                    fulfilledBy { keystoneAuthStrategyConfigured() }
                }

                /** All private endpoints must only be accessible after authentication. */
                requirement {
                    name = "All Endpoints Must Have Authentication Enabled"

                    fulfilledBy { endpointsAreAuthenticated() }
                }

                /** All endpoints have token-based authentication. */
                requirement {
                    name = "Token-based Authentication"

                    // Checks if all access tokens used for authentication are validated by the
                    // token-based authentication and if they come from the request context.
                    fulfilledBy {
                        tokenBasedAuthenticationWhenRequired() and
                            usesSameTokenAsCredential() and
                            hasDataFlowToToken() and
                            useKeystoneForAuthentication()
                    }
                }

                /**
                 * When authorizing an HTTP request, the caller’s domain/project is used in the
                 * authorization check. When a user reads data from or writes data to a database,
                 * the user’s domain is used as a filter in the database query.
                 */
                requirement {
                    name = "Domain/Project used in Authorization Checks"

                    fulfilledBy {
                        endpointAuthorizationBasedOnDomainOrProject() and
                            databaseAccessBasedOnDomainOrProject()
                    }
                }

                /**
                 * Data flows from user requests are not stored in global variables (since they are
                 * assumed to be domain-independent) or they are deleted after the request is
                 * answered.
                 */
                requirement {
                    name = "No Data Flows to Globals"

                    fulfilledBy { noDataFlowsToGlobals<HttpRequest>() }
                }

                /**
                 * An access request to a resource from another domain is answered with
                 * “unauthorized”, i.e. no indirect information leakages via answers like “not
                 * found” or “already exists” happen.
                 */
                requirement {
                    name = "Not Unauthorized Access for Other Domains"

                    fulfilledBy {
                        unauthorizedResponseFromAnotherDomainQuery(
                            policy = UnauthorizedResponsePolicy()
                        )
                    }
                }
            }
        }
    }
}
