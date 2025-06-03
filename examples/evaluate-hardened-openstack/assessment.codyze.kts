/*
 * This file is part of the OpenStack Checker
 */
package example

project {
    manualAssessment {
        of("Contributor-Diversity-Nova") {
            val expectedValue = 2
            val actualValue = 14

            /* The expected value for contributor diversity is >= 2, so the KPI is fulfilled for
            the nova Flamingo release */
            actualValue > expectedValue
        }

        of("Release-Reviewers-Nova") {
            val expectedValue = 10
            val actualValue = 27

            /* Number of reviewers involved in one release is expected to be >= 10, so the KPI is
            fulfilled for the nova Flamingo release */
            actualValue > expectedValue
        }

        of("Branch-Protection") {
            /* Branch protection mechanisms, including code approvals, automated gate tests, and automated testcases,
            are active in Gerrit, so the KPI is fulfilled for the nova Flamingo release */
            true
        }
    }
}
