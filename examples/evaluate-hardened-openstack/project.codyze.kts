/*
 * This file is part of the OpenStack Checker
 */
import de.fraunhofer.aisec.openstack.queries.encryption.stateOfTheArtEncryption
import example.queries.verySpecificQuery

project {
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
            }
        }

        /**
         * This block describes the requirements that need to be checked. Requirements can either be
         * automatically checked by a query or by manual inspection.
         */
        requirements {
            requirement("Check Security Target Description for Consistency") { byManualCheck() }
            requirement("State-of-the-Art Encryption Algorithm") {
                byQuery { result -> stateOfTheArtEncryption(result) }
            }
            requirement("Very Specific Requirement") { byQuery(::verySpecificQuery) }
        }
    }
}
