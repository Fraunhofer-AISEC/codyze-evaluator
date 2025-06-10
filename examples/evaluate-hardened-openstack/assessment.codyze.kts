/*
 * This file is part of the OpenStack Checker
 */
package example

project {
    manualAssessment {
        of("Contributor-Diversity-Nova") {
            /**
             * The expected number of contributors for the nova project. This number is based on the
             * ecosystem analysis of the OpenStack project.
             */
            val expectedValue = 2

            /**
             * The actual number of contributors for the nova project. This number is based on the
             * ecosystem analysis of the OpenStack project.
             */
            val actualValue = 12

            // The expected value for contributor diversity is >= 2, so the KPI is fulfilled for the
            // nova 2024.2 release
            actualValue > expectedValue
        }

        of("Release-Reviewers-Nova") {
            /**
             * The expected number of reviewers involved in one release of the nova project. This
             * number is based on the ecosystem analysis of the OpenStack project.
             */
            val expectedValue = 10

            /**
             * The actual number of reviewers involved in one release of the nova project. This
             * number is based on the ecosystem analysis of the OpenStack project.
             */
            val actualValue = 45

            // Number of reviewers involved in one release is expected to be >= 10, so the KPI is
            // fulfilled for the nova 2024.2 release
            actualValue > expectedValue
        }

        of("Branch-Protection") {
            // Branch protection mechanisms, including code approvals, automated gate tests, and
            // automated testcases, are  active in Gerrit, so the KPI is fulfilled for the nova
            // 2024.2 release
            true
        }

        of("Sec-Targets-Defined") {
            // I had an initial look but am not really sure yet.
            Undecided
        }

        of("Other-KPIs") { (2 gt 1).assume(AssumptionType.SoundnessAssumption, "Math is sound") }
    }
}
