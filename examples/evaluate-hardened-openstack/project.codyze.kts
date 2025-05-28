/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.openstack.queries.encryption.stateOfTheArtEncAlgorithms
import de.fraunhofer.aisec.openstack.queries.file.OnlyWritesFromASecret
import de.fraunhofer.aisec.openstack.queries.file.restrictiveFilePermissionsAreAppliedWhenWriting
import de.fraunhofer.aisec.openstack.queries.keymanagement.noLoggingOfSecrets
import de.fraunhofer.aisec.openstack.queries.keymanagement.secretsAreDeletedAfterUsage
import example.queries.verySpecificQuery

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
                module("cinder") {
                    directory = "toe/modules/cinder"
                    include("cinder")
                    exclude("tests", "drivers")
                }

                module("magnum") {
                    directory = "toe/modules/magnum"
                    include("magnum")
                    exclude("tests", "drivers")
                }

                module("oslo.config") {
                    directory = "toe/libraries/oslo.config"
                    include("oslo_config")
                }
            }
        }

        /**
         * This block describes the requirements that need to be checked. Requirements can either be
         * automatically checked by a query or by manual inspection.
         */
        requirements {
            requirement("RQ-SEC-TARGET") {
                name = "Check Security Target Description for Consistency"

                fulfilledBy { manualAssessmentOf("SEC-TARGET") }
            }

            category("GENERAL") {
                name = "General Security Requirements"
                description =
                    "This describes generic security requirements for all OpenStack components."

                requirement {
                    name = "Apply Restrictive File Permissions"
                    description =
                        "See https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html."

                    // This query checks if restrictive file permissions are applied when writing
                    // files. But only
                    // if the file is written from a secret.
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

            category("byok") {
                name = "Bring Your Own Key (BYOK)"
                description =
                    "Ensure that the OpenStack deployment supports Bring Your Own Key (BYOK) " +
                        "for disk encryption, allowing users to manage their own encryption keys."

                requirement("State-of-the-Art Encryption Algorithm") {
                    fulfilledBy { stateOfTheArtEncAlgorithms() }
                }

                requirement("Very Specific Requirement") { fulfilledBy { verySpecificQuery() } }
            }
        }
    }
}
