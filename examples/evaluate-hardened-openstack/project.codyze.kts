/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.codyze.dsl.fulfilledBy
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.queries.authorization.*
import de.fraunhofer.aisec.codyze.queries.encryption.*
import de.fraunhofer.aisec.codyze.queries.file.*
import de.fraunhofer.aisec.codyze.queries.keymanagement.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import example.queries.keystoneAuthStrategyConfigured

include {
    Tagging from "tagging.codyze.kts"
    ManualAssessment from "assessment.codyze.kts"
    AssumptionDecisions from "assumptions.codyze.kts"
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

                /** [OsloContext] is a library for managing contexts in OpenStack. */
                module("oslo.context") {
                    directory = "toe/libraries/oslo.context"
                    include("oslo_context")
                    exclude("tests")
                }

                /** [OsloPolicy] is a library for managing contexts in OpenStack. */
                module("oslo.policy") {
                    directory = "toe/libraries/oslo.policy"
                    include("oslo_policy")
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

                /**
                 * [KeystoneAuth] is a library that provides authentication handling for OpenStack
                 * Keystone, the identity service.
                 */
                module("keystoneauth") {
                    directory = "toe/libraries/keystoneauth"
                    include("keystoneauth1")
                    exclude("tests")
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

                    // This query checks that temporary files are always deleted after use (i.e.m.
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
                        val notLeaked =
                            keyNotLeakedThroughOutput(
                                isLeakyOutput = Node::dataLeavesOpenStackComponent
                            )
                        val keyReachable =
                            encryptionKeyOriginatesFromSecureKeyProvider(
                                isSecureKeyProvider = HttpEndpoint::isSecureOpenStackKeyProvider
                            )
                        val notLeakedAndReachable = notLeaked and keyReachable
                        val q2 = keyIsDeletedFromMemoryAfterUse()

                        notLeakedAndReachable and q2
                    }
                }

                /** The key must be protected when in transit. */
                requirement {
                    name = "Transport Encryption of Key"

                    fulfilledBy(::transportEncryptionForKeys)
                }

                /**
                 * The key must only be accessible by a valid user and through the REST API of
                 * [Barbican].
                 */
                requirement {
                    name = "Key Accessible Only By Valid User"

                    fulfilledBy(::keyOnyAccessibleByAuthenticatedEndpoint)
                }
            }

            /**
             * This category contains requirements related to multi-tenancy in OpenStack, ensuring
             * that the system is designed to support multiple tenants securely and efficiently.
             */
            category("Multi-Tenancy") {
                name = "Multi-Tenancy"

                /** All services need to use Keystone as their authentication strategy. */
                requirement {
                    name = "Use Keystone for Authentication"

                    fulfilledBy(::keystoneAuthStrategyConfigured)
                }

                /**
                 * All endpoints for [Cinder] and [Barbican] must only be accessible after
                 * authentication.
                 */
                requirement {
                    name = "All Endpoints Must Have Authentication Enabled"

                    fulfilledBy {
                        endpointsAreAuthenticated(
                            shouldHaveAuthentication = HttpEndpoint::isCurrentBarbicanOrCinderAPI
                        )
                    }
                }

                /**
                 * All endpoints must use access tokens from a valid [tokenProvider]. The access
                 * tokens used for authentication are validated by the token-based authentication,
                 * and they must come from the request context. Finally, the user/domain/project
                 * information in the token must be used in the authentication process.
                 */
                requirement {
                    name = "Token-based Authentication"

                    fulfilledBy {
                        tokenBasedAuthenticationWhenRequired(
                            requiresAuthentication = HttpEndpoint::isCurrentBarbicanOrCinderAPI,
                            validTokenProvider = tokenProvider,
                        ) and
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
                        val q1 = endpointAuthorizationBasedOnDomainOrProject()
                        val q2 = databaseAccessBasedOnDomainOrProject()
                        q1 and q2
                    }
                }

                /**
                 * Data flows from user requests are not stored in global variables (since they are
                 * assumed to be domain-independent) or they are deleted after the request is
                 * answered.
                 */
                requirement {
                    name = "No Data Flows to Globals in User-Scoped Requests"

                    fulfilledBy { noDataFlowsToGlobals<HttpRequest>() }
                }

                /**
                 * An access request to a resource from another domain is answered with
                 * “unauthorized”, i.e. no indirect information leakages via answers like “not
                 * found” or “already exists” happen.
                 */
                requirement {
                    name = "Respond with Unauthorized Access for Other Domains"

                    fulfilledBy {
                        unauthorizedResponseFromAnotherDomainQuery(
                            policy = UnauthorizedResponsePolicy()
                        )
                    }
                }

                suppressions {
                    /**
                     * This is a suppression for a query that checks for the deletion of secrets. It
                     * is known to find a violation if the secret is returned by two known endpoints
                     * in the file "secret.py" at lines 129 and 212.
                     */
                    queryTree(
                        { qt: QueryTree<Boolean> ->
                            val returnStmtLocation =
                                ((qt.children.singleOrNull()?.value as? List<*>)?.lastOrNull()
                                        as?
                                        de.fraunhofer.aisec.cpg.graph.statements.ReturnStatement)
                                    ?.location
                            returnStmtLocation
                                ?.artifactLocation
                                ?.uri
                                ?.path
                                ?.endsWith(
                                    "/examples/evaluate-hardened-openstack/toe/modules/barbican/barbican/api/controllers/secrets.py"
                                ) == true &&
                                (returnStmtLocation.region.startLine == 129 ||
                                    returnStmtLocation.region.startLine == 212)
                        } to true
                    )

                    queryTree(
                        { qt: QueryTree<Boolean> ->
                            val lastNode =
                                (qt.children.singleOrNull()?.value as? List<*>)?.lastOrNull()
                            lastNode is MemberCallExpression &&
                                lastNode.name.localName == "execute" &&
                                ((lastNode.location
                                    ?.artifactLocation
                                    ?.uri
                                    ?.toString()
                                    ?.endsWith("cinder/volume/flows/manager/create_volume.py") ==
                                    true &&
                                    (lastNode.location?.region?.startLine == 605 ||
                                        lastNode.location?.region?.startLine == 585)) ||
                                    (lastNode.location
                                        ?.artifactLocation
                                        ?.uri
                                        ?.toString()
                                        ?.endsWith("cinder/utils.py") == true &&
                                        lastNode.location?.region?.startLine == 172) ||
                                    (lastNode.location
                                        ?.artifactLocation
                                        ?.uri
                                        ?.toString()
                                        ?.endsWith(
                                            "magnum/conductor/handlers/common/cert_manager.py"
                                        ) == true &&
                                        (lastNode.location?.region?.startLine == 197 ||
                                            lastNode.location?.region?.startLine == 169)))
                        } to false
                    )

                    /**
                     * This access to the DB explicitly allows to read the default volume type of
                     * all projects.
                     */
                    queryTreeById("00000000-297e-6d16-0000-0000000004f4" to true)

                    /**
                     * This line is the following assignment `new_key = keymgr.get(context,
                     * new_key_id)`. The `CallExpression` is tagged with a `GetSecret` and a
                     * `HttpRequest`. With this, we have several DFG paths reaching new_key,
                     * including the `MemberCallExpression`, its base (`keymgr`), the reference
                     * `context? and the reference `new_key_id`, too. However, we're only interested
                     * in the path across the `HttpRequest` which should supersede the other data
                     * flows. As the pass does not replace existing DFG edges but only adds new
                     * ones, this is not accurately modeled (to not lose the connections of the
                     * "real code").
                     *
                     * We suppress every dataflow path containing a node which is not the
                     * `HttpRequest` since this one invalidates all the rest. The CPG models the
                     * rest as alternative paths, which is not what we want here as it is not
                     * correct.
                     */
                    queryTree(
                        { qt: QueryTree<Boolean> ->
                            ((qt.children.singleOrNull()?.value as? List<*>)?.any {
                                it is Node &&
                                    it !is HttpRequest &&
                                    it.location
                                        ?.artifactLocation
                                        ?.uri
                                        ?.path
                                        ?.endsWith(
                                            "/examples/evaluate-hardened-openstack/toe/modules/cinder/cinder/volume/flows/manager/create_volume.py"
                                        ) == true &&
                                    (it.location?.region?.startLine == 515)
                            } == true)
                        } to true
                    )
                }
            }
        }
    }
}
