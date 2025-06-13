/*
 * This file is part of the OpenStack Checker
 */
@file:OptIn(ExperimentalUuidApi::class)

import de.fraunhofer.aisec.codyze.dsl.fulfilledBy
import de.fraunhofer.aisec.codyze.profiles.openstack.*
import de.fraunhofer.aisec.codyze.queries.authentication.*
import de.fraunhofer.aisec.codyze.queries.authorization.*
import de.fraunhofer.aisec.codyze.queries.encryption.*
import de.fraunhofer.aisec.codyze.queries.file.*
import de.fraunhofer.aisec.codyze.queries.isolation.*
import de.fraunhofer.aisec.codyze.queries.keymanagement.*
import de.fraunhofer.aisec.cpg.graph.concepts.http.*
import de.fraunhofer.aisec.cpg.graph.statements.expressions.MemberCallExpression
import example.queries.keystoneAuthStrategyConfigured
import kotlin.uuid.ExperimentalUuidApi

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
                 * [Nova] is the OpenStack compute service that provides virtual machines and
                 * manages compute resources. It is responsible for launching and managing
                 * instances.
                 */
                module("nova") {
                    directory = "toe/modules/nova"

                    /**
                     * However, in our scenario, [Cinder] is directly interacting with "libvirt" to
                     * encrypt disk images. [Nova] is not used in this context. Therefore, we only
                     * include [Nova] in the Ecosystem analysis, but not in the source code
                     * analysis.
                     */
                    exclude("nova")
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
                 * by a secure key provider, not leaked through other output and deleted after use.
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
                        val q2 =
                            databaseAccessBasedOnDomainOrProject(
                                hasCheckForDomain = Node::hasCheckForDomain
                            )
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
                        val q1 =
                            unauthorizedResponseFromAnotherDomainQuery(
                                policy = UnauthorizedResponsePolicy()
                            )
                        q1
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
                     * These query trees flow through the line 515 of the file
                     * "/examples/evaluate-hardened-openstack/toe/modules/cinder/cinder/volume/flows/manager/create_volume.py".
                     * This line contains the following assignment `new_key = keymgr.get(context,
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
                    queryTreeById("00000000-5629-d9c1-ffff-ffffce05e786" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdfe7c2c4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb3260174" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000038c867d0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd0d797e6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000056e7a676" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb940bfd2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004fa51b53" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000011ae0be6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb887c492" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaab20681" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa7f3527c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006ea25035" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff090881c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000236af27f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003aaa40e2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8845641c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ecae176" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa428179" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff98859ae0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff579df2f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003189957b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003f5f538c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000077681716" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc181cfdc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000070081698" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000066c7219" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff2fb19e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005aebe9ca" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa43af25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc7b2f58f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff99af3d0f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdc26d12a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb5d2c583" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffab3d3d85" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002c662b75" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000049abc617" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd3186025" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc78949c7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff96c6bcc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe4f89031" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb6f4d7b1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc882d827" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb578f4e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffefcb6ae9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc9775f42" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbee1d744" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad53d6ce" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000400ac534" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbde848e4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbb90ebc1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcc255dd7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd7b47435" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004e47da27" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe994a441" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd1eec37" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffe087fdc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004c42c1fe" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004b49339e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000056d849fc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003ab4c188" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007d2c55a3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd6bafee" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000068b87a08" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000039f37873" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9ea6ae59" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000befbff3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000028134867" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c843209" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001d7dc069" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004e67540e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff3f8c5cb" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe21895bf" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000058abfbb1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd7830dc1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc5f50d4b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd6897f61" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000086ca166" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007e38d6d9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004d4f4334" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffce783124" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000057e4cb32" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003bc142be" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000069c4fb3e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004c55b4d4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000027d576ee" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000015f546e2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003c495289" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff9d1be6e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000a663084" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000b5fbee4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8c88acd4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9df5630e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa289ec53" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001af8b6c9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002cb59d62" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000043f4ebc5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb3fcb164" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000077ecfb18" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb13dfd5f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff9db32ff" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc1d26f75" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000165060f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff97c96190" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8d3c1949" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff52ce933" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff808ecb35" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffae9283b5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc3065f50" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9cb253a9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff91233d4b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001345b99b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff921ccbab" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9315629e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000011ec74ae" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000042d60853" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000005e7438" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002e622cb8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c81fcac" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000010f2e64e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000e44e7b9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff2215f45" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003498f360" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff84d84dab" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000002b5d15b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000003af5fbb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000202517c5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004f33b8fb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003e9f46e5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000502d475b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd156354b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005ac2cf59" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8116db00" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006ca2ff65" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8e794e8e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003e39f443" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000017e5e89c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000d50609e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000029c618a8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffbc26028" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000c56d23e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9016bc15" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad86027f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000012393865" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007f8249ff" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc1f9de1a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff91104a75" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9ba5d273" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000026e61e36" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000038c64e42" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000ac295c2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004d3a29dd" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c509638" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001b5707d8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9d798428" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000020f459a1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007133b3ec" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff00ac5fc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffaa04dfa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffde7cc586" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000c807e06" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffef11379c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000050bd486a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe37436d0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9334dc85" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006ce0d0de" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000624b48e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007ec100ea" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006151ba80" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002eaf3b2d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd50cdadd" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003cfdaac7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda6bc1fb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000070d01d7c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd5ed9759" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000009e5a6ac" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8bd3de93" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000053cb1b09" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000045f55cf8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004336a8f3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffacf1625d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbeae48f6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd93d554e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcb67973d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005b5fd19e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000114618d8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc8a8e338" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000032639ca2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8f57e0f1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004420833b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb89b0117" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002236a596" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000207bf832" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff869e6aa2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffee8f3a8c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeb676c8e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff83769ca4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9be5847d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002e9c72e3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad7384f3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffde5d1898" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc9e93cfd" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb8090cf1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffac79f693" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002b9dcc5a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000372ce2b8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffadc048aa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005d80ee5f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001b095a44" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002c975aba" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000490d12c4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000383963ee" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaeccc9e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c15db7a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004a1993fa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005e8d6f95" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002da3dbf0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002caa4d90" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa7dde283" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb36cf8e1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9749706d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002a005ed3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc54d28ed" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd9c10488" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa8d770e3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda26572a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffebb457a0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006cdd4590" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff649df9e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000082a0faa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c9deb45" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeabac940" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001a48112f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffdd25925" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007efb4715" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffcd8cac5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffec4458af" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000867e123" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ebbecca" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa649a607" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc26d2e7b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd44d5e87" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb6de181d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb7d7a67d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003900946d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe8c13a22" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8da86f8a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd02003a5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9f367000" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbbac280a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000205f5df0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa9cbf7fe" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e3ce1a0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa8078e4b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8a9847e1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff96275e3f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbc7b69e6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007a03d5cb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000cbac431" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8b91d641" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006c6f2b54" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000002d386d5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc49554a0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007a7b9bda" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9b991fa4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad56063d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff88d63f3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000031de663a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000349d1a3f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004272d850" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff855ff3d8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc68f0ca6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff94f3c31c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9bcfbaeb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000068f55088" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe6e86914" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe70718a1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002316ceed" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000020581ae8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005406904f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006d5b2fb7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000056a5fcd" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffd48254f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcb65034a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe8d449b4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd6f419a8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbad09134" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004d877f9a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcc5e91aa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa7ce2f8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff98eee282" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc6f29b02" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb5126af6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb66769d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa9835498" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ba5d0e8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff91163e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001534ec55" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000009a5d5f7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000027151c61" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000a9f6457" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003b88f7fc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8bc85247" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbe217cb7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffac937c41" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbd27ee57" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc8b704b5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003f4a6aa7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda9734c1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffef0b105c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003b00e831" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004c8ee8a7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004b955a47" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007d787c4c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006904a0b1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcdb7d697" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000572470a5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc6c8ef3a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000048eb6b8a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb6347d24" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc7c27d9a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff8ac113f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd2580598" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe43835a4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe1583b32" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000057eba124" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd5c924d4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000007ac46d9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd6c2b334" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc534b2be" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff3386b3e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000039331de6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000b2f6566" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001bc3d77c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001cbd65dc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002752edda" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004da6f981" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9de653cc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffccab5561" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000067f81f7b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005617ef6f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000039f466fb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007c6bfb16" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004a88d911" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004b826771" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000036d1df0b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd363a8c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004e1097f9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb8f3c5e6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003d7c25e3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff86195b83" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa736df4d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd0331449" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000042b239c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000403ad9e8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff881a3def" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004ec93ba8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000391ddf2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8ad8f1f4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd0b7738f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001ad12c55" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff98aeb005" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff1d4f759" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8a623b7f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000020c69700" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc9018129" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000023e591d9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8bd661c3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002800e05c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff80b71d36" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000047661aef" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff914b8f4c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffea71d6a0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8375d13b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffc2ebd39" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc95452d6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000136e0b9c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb8e375a0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000020d4458a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff84361fde" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000073a1adc8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa1a56648" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8fc5363c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000006589c2e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff852fae3e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb61941e3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000009fe1cf" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe42a29c5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd29c294f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe3309b65" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000655317b5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeebfb1c3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001513bd6a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000444cab24" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000075363ec9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004ee23322" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000043531cc4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc5759914" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000032beaaae" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000060c2632e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ce5b20b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000041598da6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000f766ba1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffee1f98b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000106ffa01" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9198e7f1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001b0581ff" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000028b85729" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff7cec384" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000078f7b174" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe640c30e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000002644b82" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000014447b8e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff6d53524" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000610034a7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8754404e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000044dcac33" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000072e064b3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000055711e49" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd7939a99" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000566aaca9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb725c319" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8542a114" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa2b1e77e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff90d1b772" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000074ae2efe" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000007651d64" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff863c2f74" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8298b257" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003259580c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000016fc467" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000c054c65" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffefe1c3f1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001de57c71" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000000763607" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000036f56c1c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000022819081" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8734c667" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff47dd801" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000060bd877" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000010a16075" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000005124a17" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe1c542d8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000078299e59" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000497f72c1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8f5df45c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000d6fbc75" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb07b7826" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000575530d2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000046c0bebc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc2385ebf" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd977ad22" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000780b02b6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003694e426" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e85b410" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000052ed4713" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbc88eb92" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb30f094e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb275b25" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffabd803e3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffee5ae030" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001fa604e5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000404490c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000484fe548" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb1c81998" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbcaa844d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe0967674" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001f9ba773" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffac48da14" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcdf2084d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff84e4cd48" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000034dfb2bc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000067ba1d1f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb2f17ad5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffcd6ef32" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffef013121" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffec427d1c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007ef96b82" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000055fd3686" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000016414270" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffae507286" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc416a916" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff88566cb3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff1f21132" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbd26d21c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003e55ec91" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffab2bf30a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8d2bdf64" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000253b0f7a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffed8605be" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff83ea613f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbb086815" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000033c15413" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000000e6e9b0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000022046d7a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007ef8b1c9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb849b410" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004b00a276" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc8de2626" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003a1450cd" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000293c3ffe" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000002205316" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007be9e9b9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000787b826d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000036b00832" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000649f0ea4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000026fb6552" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa6e8544f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004c0e4052" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000708ae0d7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000669621e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000073894206" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006f4e4090" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000053fb0582" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc2c47d55" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff83dfb565" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffebd0854f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd40717b5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007673d1f4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe00f7673" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa9093d1b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffca26c0e5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000071007991" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000606c077b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000632abb80" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdbe3a77e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff322f5e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000271b0534" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb4192238" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff90bfc94b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000c5b9124" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc03e48d9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffd4b9400" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000212175a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9cab4328" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc2d7fa01" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff887f6c4c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005316c888" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc035f530" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000085037a4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa154323f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000065447bf3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001a0d1e3d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe732b3da" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e957e3a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaf29f050" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000314c6ca0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000051a56ed5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbb411354" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9ee3de93" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000021065ae3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd0c70098" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9fdd6cf3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8e4f6c7d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbc5324fd" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa72f4f1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8012578a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffae16100a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc289eba5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9c35dffe" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff91a05800" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff90a6c9a0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000012c945f0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcc903f2a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffa93f7aa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffde1e3fa0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005f472d90" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdd24b140" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe8b3c79e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000f07d345" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c6a46d3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcc2aec88" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9a47ca83" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa5d6e0e1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb7b710ed" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9b4158e3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff89b3586d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffad1c923" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000071652f15" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdeae40af" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002125d4ca" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff03c4125" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000cb1f92f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffef42b2c5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002996cab8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003b76fac4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001f0142ba" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001e07b45a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004fead65f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000d734244" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa02a30aa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff98b38e07" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc6b74687" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa948001d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdb2b2222" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb4d7167b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa418e7d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002b6a7c6d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000e7fc37a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002aa34bee" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000200dc3f0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001f143590" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000050f75795" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa136b1e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003c837bfa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007d022fe1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8891463f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007dfbbe41" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffff24ac31" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006c6dbdcb" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9a71764b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaee551e6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000076d2848e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000ee1b4a4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffedf3dbd8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9aa452a2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000295228c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffccdbe032" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000001d3bd96" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff98381917" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006c773d4e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd75a6b3b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffee99b99e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa48000d8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc59d84a2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005be2cb38" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005ea17f3d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002291c8f1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000754e0e6a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000044891e1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9c998e13" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000311fd205" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaefd55b5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000008239d09" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe706193f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000019e083a2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e68e39f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa12797a4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006517e158" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffadcbea25" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000037388433" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001b14fbbf" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005d8c8fda" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ca2fc35" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ba96dd5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004918b43f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9f42117b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e48831b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbbb7c985" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8db41105" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000206aff6b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd02ba520" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa9d79979" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9632ffba" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007a0f7746" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8aa3e95c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbc870b61" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa8132fc6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8b9d77bc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000cc665ac" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffde68ba13" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ea8145e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc9f4de78" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb814ae6c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9bf125f8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffac85980e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad7f266e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000038450569" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004a253575" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002cb5ef0b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaed86b5b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005e991110" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c217cf5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002daf7d6b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa8e3125e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc558ca68" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff975511e8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002a0c004e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa7e983fe" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb3789a5c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd9cca603" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeac66abb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001ca98cc0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffebbff91b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff6558119" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000835b125" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda31f8a5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006ce8e70b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffec4ffa2a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000873829e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007f06e890" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffdddfaa0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffce46c40" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001a53b2aa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ec78e45" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe8ccdb9d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb7e347f8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd4590002" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb6e9b998" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa6554782" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc278cff6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000390c35e8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe9faaf73" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8209df89" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000074a577cf" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000b09d350" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff7e4dab3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8a9bc919" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000735c7ab6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbe93d86c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000619f941d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000008794cc9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000040821053" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffaa38eb8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007097fced" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa7bcfc87" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003fcc2c9d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006bff93bc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd59b383b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9df51a18" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff6b70e64" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005ea7de4e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdc707513" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005b478723" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000049b986ad" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8c311ac8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000065dd0f21" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005a4df8c3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000077bd3f2d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffccb8276f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9eb46eef" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb0426f65" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaf48e105" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe12c030a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbad7f763" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000316b5d55" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9b315062" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006a47bcbd" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeb70aaad" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000058b9bc47" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000694e2e5d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff86bd74c7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000074dd44bb" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff829019e5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd2cf7430" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000401885ca" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000050acf7e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000051a68640" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006e1c3e4a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005c3c0e3e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005a77a48b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003d085e21" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002c73ec0b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003e01ec81" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbf2ada71" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004897747f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006eeb8026" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe013f230" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffc89aa3a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffce85f1ba" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000613ce020" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdf1a63d0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeaa97a2e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000010fd85d5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdf0770fa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe99cf8f8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd797084" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000ff1049f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000060305eea" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffde0de29a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffb7d2904" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe10c8923" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004e559abd" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006a792331" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005eea0cd3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff90cd2ed8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007c59533d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005fe39b33" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffba9a25ea" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcf0e0185" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8c966d6a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001f4d5bd0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa8b9f5de" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9d2adf80" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9e246de0" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffba798194" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000050dddd15" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000634cb5b3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffad322a10" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe53aed9a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9f5c6bff" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000181557fd" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002f54a660" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000006587164" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9c9db7fa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000641f6756" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffffa83c2d7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe9beb0cc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff81cde0e2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000193fe72" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa34467de" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000134c2d7d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000108d7978" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000592aaf18" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8c05197b" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd73c7731" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007a4832e2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002121eb8e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003708e8d8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe20cb965" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff96d55baf" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001b5dbbac" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001e1c6fb1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000063faf14c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffae14aa12" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004cb464d2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000043b2c4e0" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000489c3826" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd249823" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000036df518d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000015c1cdc3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcfe34c28" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffddb90a39" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005fdb8689" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff93d395dc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9811b6ff" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000559a22e4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000071bdab58" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe851114a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff839ddb64" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000662e94fa" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006728235a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff929e10fe" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff75146e4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa711ec99" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff80bde0f2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000752eca94" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000649a587e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000762858f4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd95a0cbb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006c10fb21" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe9ee7ed1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeae80d31" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff57d952f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001bd1a0d6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000075dc53b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000665840c2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000038548842" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcb0b76a8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007acc1c5d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000048e8fa58" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000049e288b8" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000547810b6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005d872277" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000681caa75" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000079fcda81" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005c8d9417" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdeb01067" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8e70b61c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004bf92201" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007659bf68" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeced255a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006acaa90a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9cadcb0f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006bc4376a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8839ef74" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005a3636f4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdaee9dbc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc67ac221" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa050a17" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff987709a1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002b2df807" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa90b7bb7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb49a9215" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001cde220c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006d1d7c57" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffebf48e67" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff68a1665" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeafb0007" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000086a4671" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda668df1" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffaa950b26" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd898c3a6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbc230b9c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc6b8939a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffed0c9f41" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbb297d3c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003d4bf98c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000330081f7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcb0fb20d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000707da04c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffda1944cb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000187e260f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000076be1d19" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9fba5215" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000fc217b4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd3b26168" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000055a0994f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001d97d5c5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000d0363af" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff887b03b2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb83836e9" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002045d799" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8836a783" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff82023dbf" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000018669940" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd7eadeb5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa3f2cf62" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007af69a66" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000013fa9501" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8cb380ff" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000059d9169c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000113be0fc" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000021d05312" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff904694f6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002e34e666" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9625b650" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004223fcd3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffabbfa152" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000291a2518" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbf7e8099" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001d2e5403" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000119f3da5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000010acb8f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001298cc05" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002f0e840f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff93c1b9f5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000043825faa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8f6ed6e7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000006023cd9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff84d94ee9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb5c2e28e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa14f06f3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000734b4e73" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff83dfc089" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002fde66a7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001e506631" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb1075497" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004c541eb1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000060c7fa4c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002ee4d847" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003a73eea5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa2105008" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb39e507e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd0140888" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbe33d87c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000034c73e6e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe487e423" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb2a4c21e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000022ec7a41" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000065640e5c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000050f032c1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003380ec57" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003f1002b5" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000347a7ab7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb5a368a7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe5946559" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa31cd13e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb3b14354" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbf4059b2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffb4aad1b4" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd12089be" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000035d3bfa4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000030d2edc2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002543d764" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa76653b4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005726f969" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000014af654e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000042b31dce" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000263d65c4" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003ede9c41" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005b54544b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006fc82fe6" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004974243f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc0078a31" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003de50de1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002d509bcb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000612d4cee" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000072bb4d64" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007d50d562" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000071c1bf04" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8f31056e" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa3a4e109" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff3e43b54" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc41bab4a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005c2adb60" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff88f02f9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe6d21c60" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007fd616fb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000fce515c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007d1762f6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff8dabd50c" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc5b49896" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000043c660af" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00004f5f929c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000040c687a7" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd94b4b46" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa2b14915" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003c5ec2b1" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000014244f3c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007c151f26" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000047863b4c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000072d9213d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdc74c5bc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffac5a5a72" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdf34c4d5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff6741338" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000745196e8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd77de3c" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000667bd8d7" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000063bd24d2" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002a6c228b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000012efa94f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000075c97194" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeb3027ec" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000029dcec6f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff82d5fd64" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000026bc4ccb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003d99965a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000027099455" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbd6defd6" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9440b593" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff841a23ad" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001c2953c3" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000223e8292" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006c23f6ef" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005e4e38de" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffee46733f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00005b8f84d9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffd70724dc" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa42cba79" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc54a3e43" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002345e024" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00006d13cd66" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000004c0ff67" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffef54111b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000599fa360" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000054255b9b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001bc15336" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00001fc4cabb" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007a418702" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc84bcc2d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff91c904ed" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa7d13487" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000011306eb3" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffa4ba78a8" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffeff1d65e" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002c018caa" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff92fd920f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002942d8a5" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbbf9c70b" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000071e00e45" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000039d74abb" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbe8e1d09" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000054f2788a" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffc26e465f" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffdd26b179" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00007535e18f" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00002addce9d" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00000f6a5551" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffcd35b216" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffafe0414a" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000039b4bb1d" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffe7631367" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9a20dbd9" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffab8613ed" to true)
                    queryTreeById("00000000-5629-d9c1-0000-00003ed33d62" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-fffff9b0e349" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffff9d994bac" to true)
                    queryTreeById("00000000-5629-d9c1-0000-0000778f2582" to true)
                    queryTreeById("00000000-5629-d9c1-0000-000044d6c5a2" to true)
                    queryTreeById("00000000-5629-d9c1-ffff-ffffbd2566ab" to true)
                }
            }

            /** This category contains requirements related to the ecosystem of OpenStack. */
            category("Ecosystem") {
                /**
                 * Identify and assess open and unresolved vulnerabilities in the project's codebase
                 * or dependencies, using services like OSV, to ensure important fixes are
                 * integrated.
                 */
                requirement {
                    name = "No Known Vulnerabilities"

                    fulfilledBy {
                        manualAssessmentOf("Ecosystem-G1-Checking-Known-Vulnerabilities")
                    }
                }

                /**
                 * Assure that timely updates of dependencies are continuously integrated, using
                 * tools like proposal bots. Verify active development and maintenance activities,
                 * ensuring adherence to security policies and having proper licenses.
                 */
                requirement {
                    name = "Continuous Maintenance"

                    fulfilledBy {
                        manualAssessmentOf(
                            "Ecosystem-G2-Checking-Continuous-Maintenance-KPI-Dependency-Update-Tool"
                        ) and
                            manualAssessmentOf(
                                "Ecosystem-G2-Checking-Continuous-Maintenance-KPI-Security-Policy"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G2-Checking-Continuous-Maintenance-KPI-License"
                            )
                    }
                }

                /**
                 * Review adherence to best practices for open-source projects, including
                 * key-hardening headers and dynamic analysis tools for major releases. Check the
                 * project's OSSF best practices badge.
                 */
                requirement {
                    name = "CI/CD Best Practices"

                    fulfilledBy { manualAssessmentOf("Ecosystem-G3-Checking-CII-Best-Practices") }
                }

                /**
                 * Verify the execution of CI tests and mandatory and correct integration of tools
                 * like Zuul before code merges. Also look into the usage of fuzzing, SAST tools,
                 * and evaluate the testing interface consistency across projects.
                 */
                requirement {
                    name = "Continuous Testing"

                    fulfilledBy {
                        manualAssessmentOf(
                            "Ecosystem-G4-Checking-Continuous-Testing-KPI-CI-Tests"
                        ) and
                            manualAssessmentOf(
                                "Ecosystem-G4-Checking-Continuous-Testing-KPI-Fuzzing"
                            ) and
                            manualAssessmentOf("Ecosystem-G4-Checking-Continuous-Testing-KPI-SAST")
                    }
                }

                /**
                 * Ensure that CI/CD security settings are properly configured, including Gerrit
                 * settings, branch protection, token permissions, and the evaluation of dangerous
                 * workflows to prevent unauthorized code changes.
                 */
                requirement {
                    name = "CI/CD Security"

                    fulfilledBy {
                        manualAssessmentOf(
                            "Ecosystem-G5-Checking-CI/CD-Security-KPI-Gerrit-Settings"
                        ) and
                            manualAssessmentOf(
                                "Ecosystem-G5-Checking-CI/CD-Security-KPI-Branch-Protection"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G5-Checking-CI/CD-Security-KPI-Dangerous-Workflows"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G5-Checking-CI/CD-Security-KPI-Token-Permissions"
                            )
                    }
                }

                /**
                 * Ensure that code changes undergo human reviews, assessing contributor diversity,
                 * and reviewing metrics related to code contributions, such as contributor
                 * frequency and code review participation.
                 */
                requirement {
                    name = "Code Contributions and Reviews"

                    fulfilledBy {
                        manualAssessmentOf(
                            "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Code-Review"
                        ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contributors"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contributor-Diversity"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Do-Not-Merge-Votings"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Filed-To-Resolved-Bugs-Ratio"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Abandoned-Change-Requests"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Reviewers"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Reviewer-Diversity"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contribution-Frequency"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Review-Activity"
                            )
                    }
                }

                /**
                 * Check for binary artifacts in repositories, assess dependency pinning, evaluate
                 * packaging and signed releases to mitigate build risks, ensuring reproducibility
                 * and security of artifacts.
                 */
                requirement {
                    name = "Build Risks"

                    fulfilledBy {
                        manualAssessmentOf(
                            "Ecosystem-G7-Checking-Build-Risks-KPI-Binary-Artifacts"
                        ) and
                            manualAssessmentOf(
                                "Ecosystem-G7-Checking-Build-Risks-KPI-Pinned-Dependencies"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G7-Checking-Build-Risks-KPI-Packaging"
                            ) and
                            manualAssessmentOf(
                                "Ecosystem-G7-Checking-Build-Risks-KPI-Signed-Releases"
                            )
                    }
                }
            }
        }
    }
}
