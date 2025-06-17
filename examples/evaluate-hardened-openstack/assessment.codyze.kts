/*
 * This file is part of the OpenStack Checker
 */
package example

import de.fraunhofer.aisec.cpg.query.NotYetEvaluated

project {
    manualAssessment {
        of("Ecosystem-G1-Checking-Known-Vulnerabilities") {
            /** The expected fulfillment for known vulnerabilities in the Nova project. */
            val expectedValue = true

            /**
             * A search for OpenStack vulnerabilities in the github.com/openstack/nova package
             * results in various potential vulnerabilities. One listed vulnerability, for example,
             * is CVE-2022-47951 which shows that the vulnerability has been fixed. Also, the
             * vulnerability does not affect the 2024.2 release. One OSSA (2024-002 has been
             * released which affects Nova in the 2024.2 release; a patch, however, has been
             * released.
             */
            val actualValue = true

            // The fulfillment for known vulnerabilities is met, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G2-Checking-Continuous-Maintenance-KPI-Dependency-Update-Tool") {
            /** The expected fulfillment for the dependency update tool in the Nova project. */
            val expectedValue = true

            /** The OpenStack proposal bot is in active use. */
            val actualValue = true

            // The dependency update tool is active, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G2-Checking-Continuous-Maintenance-KPI-Security-Policy") {
            /** The expected fulfillment for the security policy in the Nova project. */
            val expectedValue = true

            /**
             * The OpenStack projects have a common security policy defined, including information
             * on vulnerability management
             */
            val actualValue = true

            // The security policy is defined, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G2-Checking-Continuous-Maintenance-KPI-License") {
            /** The expected fulfillment for the license in the Nova project. */
            val expectedValue = true

            /** All OpenStack projects have a license defined. */
            val actualValue = true

            // The license is defined, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G3-Checking-CII-Best-Practices") {
            /** The expected fulfillment for the basic CII best practices in the Nova project. */
            val expectedValue = true

            /**
             * OpenStack has the passing batch. However, looking at the gold level, some
             * security-related criteria are not fulfilled. These refer to the key hardening headers
             * Content Security Policy (CSP), HTTP Strict Transport Security (HSTS),
             * X-Content-Type-Options, and X-Frame-Options which are not used in the OpenStack
             * ecosystem.
             */
            val actualValue =
                false // true for the basic level, but some gold level criteria are not fulfilled
            // and should be accepted as such

            actualValue eq expectedValue
        }

        of("Ecosystem-G4-Checking-Continuous-Testing-KPI-CI-Tests") {
            /** The expected fulfillment for CI tests in the Nova project. */
            val expectedValue = true

            /**
             * The individual checks for the opendev repository, repository template, zuul.yaml,
             * zuul job definitions, check and gate pipelines, tox.ini file, the test directory, and
             * gerrit 'verified' and 'workflow' parts were successful.
             */
            val actualValue = true

            // The CI tests are successful, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G4-Checking-Continuous-Testing-KPI-Fuzzing") {
            /** The expected fulfillment for fuzzing in the Nova project. */
            val expectedValue = true

            /**
             * CI files (such as the Nova CI file) do not indicate a usage of fuzzing tools in the
             * pipeline. Also, the security guide does not mention fuzzing tools.
             */
            val actualValue = false

            // Fuzzing is not used, therefore the KPI
            // is not fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G4-Checking-Continuous-Testing-KPI-SAST") {
            /** The expected fulfillment for SAST in the Nova project. */
            val expectedValue = true

            /** The OpenStack documentation or CI does not stipulate SAST usage. */
            val actualValue = false

            // SAST is not used, therefore the KPI
            // is not fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G5-Checking-CI/CD-Security-KPI-Gerrit-Settings") {
            /** The expected fulfillment for Gerrit settings in the Nova project. */
            val expectedValue = true

            /**
             * Project is listed, config exists, access rights are correct, and review and workflow
             * configs are proper.
             */
            val actualValue = true

            // The Gerrit settings are correct, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G5-Checking-CI/CD-Security-KPI-Branch-Protection") {
            /** The expected fulfillment for branch protection in the Nova project. */
            val expectedValue = true

            /**
             * Code must be approved by at least one core-reviewer and code must pass automated gate
             * tests and automated testcases. These protections account to tier 4 (of 5) of OSSF
             * criteria.
             */
            val actualValue = false // set to false because not all criteria are fully met

            actualValue eq expectedValue
        }

        of("Ecosystem-G5-Checking-CI/CD-Security-KPI-Dangerous-Workflows") {
            /** The expected fulfillment for dangerous workflows in the Nova project. */
            val expectedValue = true

            /** Project is listed correctly and pipeline definition has not submit: true field. */
            val actualValue = true

            // Dangerous workflows are correctly configured, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G5-Checking-CI/CD-Security-KPI-Token-Permissions") {
            /** The expected fulfillment for token permissions in the Nova project. */
            val expectedValue = true

            /** Analogous to dangerous workflows results. */
            val actualValue = true

            // The token permissions are correctly configured, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Code-Review") {
            /** The expected fulfillment for code review in the Nova project. */
            val expectedValue = true

            /** Code changes are reviewed by humans with +2 votes. */
            val actualValue = true

            // The code review is fulfilled, therefore the KPI is fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contributors") {
            /** The expected fulfillment for the number of contributors in the Nova project. */
            val expectedValue = 2

            /**
             * The actual status of fulfillment for the number of contributors in the Nova project.
             */
            val actualValue = 12

            // The number of contributors is gt 2, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue gt expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contributor-Diversity") {
            /** The expected fulfillment for the contributor diversity in the Nova project. */
            val expectedValue = 2

            /**
             * The actual status of fulfillment for the number of contributors in the Nova project.
             */
            val actualValue = 6

            // The number of contributor affiliations is gt 2, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue gt expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Do-Not-Merge-Votings") {
            /** The expected fulfillment for Do-not-merge votings in the Nova project. */
            val expectedValue = 5

            /**
             * The actual status of fulfillment for the number of contributors in the Nova project.
             */
            val actualValue = 6

            // The number of Do-not-merge votings is gt5, therefore the KPI
            // is not fulfilled for the Nova 2024.2 release
            actualValue le expectedValue
        }

        of(
            "Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Filed-To-Resolved-Bugs-Ratio"
        ) {
            /**
             * The expected fulfillment for the Filed-to-resolved bugs ratio in the Nova project.
             */
            val expectedValue = 3

            /** There were 132 filed bugs and 50 resolved bugs in the Nova project. */
            val actualValue = 132 / 50

            // The value of the Filed-to-resolved bugs ratio is lt3, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue lt expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Abandoned-Change-Requests") {
            /** The expected fulfillment for abandoned change requests in the Nova project. */
            val expectedValue = 10

            /** There were 5 abandoned change requests in the Nova project. */
            val actualValue = 5

            // The number of abandoned change requests is le10, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue le expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Reviewers") {
            /** The expected fulfillment for number of reviewers in the Nova project. */
            val expectedValue = 10

            /** There were 45 reviewers in the Nova project. */
            val actualValue = 45

            // The number of reviewers is gt10, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue gt expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Reviewer-Diversity") {
            /** The expected fulfillment for number of reviewer affiliations in the Nova project. */
            val expectedValue = 2

            /** There were 18 reviewer affiliations in the Nova project. */
            val actualValue = 18

            // The number of reviewer affiliations is >2, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue gt expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Contribution-Frequency") {
            /** The expected fulfillment for contribution frequency in the Nova project. */
            val expectedValue = true

            /** There were some contributors that have not been active in the last 12 months. */
            val actualValue = false

            // The expected contributor activity was not as expected, therefore the KPI
            // is not fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G6-Checking-Code-Contributions-and-Reviews-KPI-Review-Activity") {
            /** The expected fulfillment for review activity in the Nova project. */
            val expectedValue = 100

            /** All contributions underwent a review process */
            val actualValue = 100

            // The expected review activity value was as expected, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G7-Checking-Build-Risks-KPI-Binary-Artifacts") {
            /** The expected fulfillment for binary artifacts in the Nova project. */
            val expectedValue = false

            /** No binary artifacts found. */
            val actualValue = false

            // No binary artifacts were found, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G7-Checking-Build-Risks-KPI-Pinned-Dependencies") {
            /** The expected fulfillment for pinned dependencies in the Nova project. */
            val expectedValue = true

            /** Only minimum version numbers are defined for each dependency. */
            val actualValue = false

            // Only minimum version numbers are defined, therefore the KPI
            // is partially fulfilled
            actualValue eq expectedValue
        }

        of("Ecosystem-G7-Checking-Build-Risks-KPI-Packaging") {
            /** The expected fulfillment for packaging in the Nova project. */
            val expectedValue = true

            /** Project can be found on PyPi. */
            val actualValue = true

            // The project is available on PyPi, therefore the KPI
            // is fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Ecosystem-G7-Checking-Build-Risks-KPI-Signed-Releases") {
            /** The expected fulfillment for signed releases in the Nova project. */
            val expectedValue = true

            /**
             * Releases are signed but the signatures do not seem to be visible on the releases
             * page.
             */
            val actualValue = false

            // The releases are signed, but the signatures do not seem to be visible,
            // therefore the KPI is partially fulfilled for the Nova 2024.2 release
            actualValue eq expectedValue
        }

        of("Sec-Targets-Defined") {
            // I had an initial look but am not really sure yet.
            NotYetEvaluated
        }

        of("Other-KPIs") { (2 gt 1).assume(AssumptionType.SoundnessAssumption, "Math is sound") }
    }
}
