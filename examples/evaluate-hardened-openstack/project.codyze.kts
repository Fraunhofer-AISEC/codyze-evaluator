/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.queries.authorization.*
import de.fraunhofer.aisec.codyze.queries.encryption.*
import de.fraunhofer.aisec.codyze.queries.file.*
import de.fraunhofer.aisec.codyze.queries.keymanagement.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.HttpRequest
import example.queries.keystoneAuthStrategyConfigured

include {
    Tagging from "tagging.codyze.kts"
    ManualAssessment from "assessment.codyze.kts"
}

project {
    name = "Evaluation Project for Hardened OpenStack"

    /**
     * This block describes the target of evaluation. It is used to define the properties of the ToE
     * (e.g., its name), its architecture, and the requirements that need to be checked.
     */
    toe {
        name = "Hardened OpenStack"
        description =
            "This ToE represents a version of OpenStack that is hardened " +
                "with a specific configuration to meet security requirements."
        version = "2024.2"

        /**
         * This block describes the general architecture of the ToE, including its module.
         *
         * Each module will be loaded into the graph.
         */
        architecture {
            modules {
                module("nova") {
                    directory = "toe/modules/nova"
                    include("nova")
                    exclude("tests", "drivers")
                }

                /**
                 * Cinder is the OpenStack block storage service that provides persistent block
                 * storage to instances. It supports various backends and allows users to manage
                 * volumes.
                 */
                module("cinder") {
                    directory = "toe/modules/cinder"
                    include("cinder")
                    exclude("tests", "drivers", "libvirt")
                }

                /**
                 * Barbican is the OpenStack key manager service that provides secure storage and
                 * management of secrets, such as encryption keys, passwords, and certificates.
                 */
                module("barbican") {
                    directory = "toe/modules/barbican"
                    include("barbican")
                    exclude("tests")
                }

                /**
                 * Magnum is the OpenStack container orchestration service that provides container
                 * management capabilities.
                 */
                module("magnum") {
                    directory = "toe/modules/magnum"
                    include("magnum")
                    exclude("tests", "drivers")
                }

                /**
                 * Castellan is a library for managing secrets in OpenStack, providing abstraction
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

                /** Oslo.config is a library for managing configuration files in OpenStack. */
                module("oslo.config") {
                    directory = "toe/libraries/oslo.config"
                    include("oslo_config")
                    exclude("tests")
                }

                /**
                 * Keystone Middleware is a library that provides middleware components for
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

            category("Eco-System") {
                requirement {
                    name = "No Known Vulnerabilities"
                    description =
                        "Identify and assess open and unresolved vulnerabilities in the project's codebase or dependencies, using services like OSV, to ensure important fixes are integrated."

                    fulfilledBy { manualAssessmentOf("Dependencies") }
                }

                requirement {
                    name = "Continuous Maintenance"
                    description =
                        "Assure that timely updates of dependencies are continuously integrated, using tools like proposal bots. Verify active development and maintenance activities, ensuring adherence to security policies and having proper licenses."
                }

                requirement {
                    name = "CI/CD Best Practices"
                    description =
                        "Review adherence to best practices for open-source projects, including key-hardening headers and dynamic analysis tools for major releases. Check the project's OSSF best practices badge."
                }

                requirement {
                    name = "Continuous Testing"
                    description =
                        "Verify the execution of CI tests and mandatory and correct integration of tools like Zuul before code merges. Also look into the usage of fuzzing, SAST tools, and evaluate the testing interface consistency across projects."
                }

                requirement {
                    name = "CI/CD Security"
                    description =
                        "Ensure that CI / CD security settings are properly configured, including Gerrit settings, branch protection, token permissions, and the evaluation of dangerous workflows to prevent unauthorized code changes."

                    fulfilledBy { manualAssessmentOf("Branch-Protection") }
                }
                requirement {
                    name = "Code Contributions and Reviews"
                    description =
                        "Ensure that code changes undergo human reviews, assessing contributor diversity, and reviewing metrics related to code contributions, such as contributor frequency and code review participation."

                    fulfilledBy {
                        manualAssessmentOf("Release-Reviewers-Nova") and
                            manualAssessmentOf("Contributor-Diversity-Nova")
                    }
                }

                requirement {
                    name = "Build Risks"
                    description =
                        "Check for binary artifacts in repositories, assess dependency pinning, evaluate packaging and signed releases to mitigate build risks, ensuring reproducibility and security of artifacts."
                }
            }

            category("General") {
                name = "General Security Requirements"
                description =
                    "This describes generic security requirements for all OpenStack components."

                requirement {
                    name = "Apply Restrictive File Permissions"
                    description =
                        "See https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html."

                    // This query checks if restrictive file permissions are applied when writing
                    // files. But only if the file is written from a secret.
                    fulfilledBy {
                        restrictiveFilePermissionsAreAppliedWhenWriting(
                            select = OnlyWritesFromASecret
                        )
                    }
                }

                requirement {
                    name = "Delete Secrets after Usage"
                    description =
                        "Secret data should be deleted from memory, ideally right after usage."

                    // We can use method references when we do not need to pass any parameters.
                    fulfilledBy(::secretsAreDeletedAfterUsage)
                }

                requirement {
                    name = "Secrets Must not be Logged"
                    description =
                        "Secret data must not be logged, i.e., they must not flow into a logging-statement."

                    fulfilledBy(::noLoggingOfSecrets)
                }
            }

            category("BYOK") {
                name = "Bring Your Own Key (BYOK)"
                description =
                    "Ensure that the OpenStack deployment supports Bring Your Own Key (BYOK) " +
                        "for disk encryption, allowing users to manage their own encryption keys."

                requirement {
                    name = "State-of-the-Art Disk Encryption Algorithm"
                    description =
                        "The block device encryption algorithm must be state of the art, e.g., refer to a TR."

                    fulfilledBy { stateOfTheArtEncryptionIsUsed() and minimalKeyLengthIsEnforced() }
                }

                requirement {
                    name = "Key for Disk Encryption is Kept Secure"
                    description =
                        "Given a disk encryption operation, the key used in the operation must be " +
                            "provided by a secure key provider, leaked through other output and deleted after use."

                    fulfilledBy {
                        keyNotLeakedThroughOutput() and
                            keyOnlyReachableThroughSecureKeyProvider() and
                            keyIsDeletedFromMemoryAfterUse()
                    }
                }

                requirement {
                    name = "Transport Encryption of Key"
                    description = "The key must be protected when in transit."

                    fulfilledBy { transportEncryptionForKeys() }
                }

                requirement {
                    name = "Key Accessible Only By Valid User"
                    description =
                        "The key must only be accessible by a valid user and through the REST API of barbican."

                    fulfilledBy { keyOnyAccessibleByAuthenticatedEndpoint() }
                }
            }

            category("Multi-Tenancy") {
                name = "Multi-Tenancy"
                description =
                    "This describes security requirements for tenant isolation in OpenStack environments."

                requirement {
                    name = "Use Keystone for authentication"
                    description =
                        "All authentication operations must use Keystone as the identity service."

                    fulfilledBy { keystoneAuthStrategyConfigured() }
                }

                requirement {
                    name = "All Endpoints Must Have Authentication Enabled"
                    description =
                        "All private endpoints must only be accessible after authentication."

                    fulfilledBy { endpointsAreAuthenticated() }
                }

                requirement {
                    name = "Token-based Authentication"
                    description = "All endpoints have token-based authentication."

                    fulfilledBy { tokenBasedAuthenticationWhenRequired() }
                }

                requirement {
                    name = "Domain/Project used in Authorization Checks"
                    description =
                        "When authorizing an HTTP request, the caller’s domain/project is used in the authorization check." +
                            "When a user reads data from or writes data to a database, the user’s domain is used as a filter in the database query."

                    fulfilledBy {
                        endpointAuthorizationBasedOnDomainOrProject() and
                            databaseAccessBasedOnDomainOrProject()
                    }
                }

                requirement {
                    name = "No Data Flows to Globals"
                    description =
                        "Data flows from user requests are not stored in global variables (since they are assumed to be domain-independent) or they are deleted after the request is answered."

                    fulfilledBy { noDataFlowsToGlobals<HttpRequest>() }
                }

                requirement {
                    name = "Not Unauthorized Access for Other Domains"
                    description =
                        "An access request to a resource from another domain is answered with “unauthorized”, " +
                            "i.e. no indirect information leakages via answers like “not found” or “already exists” happen."

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
