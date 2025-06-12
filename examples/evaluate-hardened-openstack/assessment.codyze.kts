/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.cpg.query.NotYetEvaluated

project {
    manualAssessment {
        ofBoolean("Contributor-Diversity-Nova") {
            /**
             * The expected number of contributors for the nova project. This number is based on the
             * ecosystem analysis of the OpenStack project.
             */
            val expectedValue = 2

            /**
             * The actual number of contributors for the nova project. This number is based on the
             * ecosystem analysis of the OpenStack project.
             */
            val actualValue = 14

            // The expected value for contributor diversity is >= 2, so the KPI is fulfilled for the
            // nova Flamingo release
            actualValue > expectedValue
        }

        ofBoolean("Release-Reviewers-Nova") {
            /**
             * The expected number of reviewers involved in one release of the nova project. This
             * number is based on the ecosystem analysis of the OpenStack project.
             */
            val expectedValue = 10

            /**
             * The actual number of reviewers involved in one release of the nova project. This
             * number is based on the ecosystem analysis of the OpenStack project.
             */
            val actualValue = 27

            // Number of reviewers involved in one release is expected to be >= 10, so the KPI is
            // fulfilled for the nova Flamingo release
            actualValue > expectedValue
        }

        ofBoolean("Branch-Protection") {
            // Branch protection mechanisms, including code approvals, automated gate tests, and
            // automated testcases, are  active in Gerrit, so the KPI is fulfilled for the nova
            // Flamingo release
            true
        }

        of("Sec-Targets-Defined") {
            // I had an initial look but am not really sure yet.
            NotYetEvaluated()
        }

        of("Other-KPIs") { (2 gt 1).assume(AssumptionType.SoundnessAssumption, "Math is sound") }
    }
}
