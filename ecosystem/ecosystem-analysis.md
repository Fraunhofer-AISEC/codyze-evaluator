# OpenStack Ecosystem Security Analysis
The purpose of this analysis is to underscore that choosing a cloud platform is a fundamental decision that influences many subsequent choices and which is dependent on many variables. Therefore, we also analyze the OpenStack ecosystem regarding the context it provides for good overall security, e.g., to address potential vulnerabilities.

The analysis methodology for the OpenStack security ecosystem focuses on examining the broader context surrounding the OpenStack system. It seeks to clarify essential questions such as which members have the authority to make decisions, the long-term goals of the project, and the rules or voting processes regarding changes, including merge requests or more significant conceptual modifications. Additionally, the quality of the publicly accessible toolchain is scrutinized, addressing how dependencies are managed to prevent supply chain attacks, how high code quality is ensured through build pipelines, and how authorship of contributions to the codebase is verified. The analysis also aims to identify further potential questions within this domain and provide answers to them.

## Analysis criteria
In the following, multiple ecosystem-related security criteria are described and analyzed for various OpenStack components. In the current state, the criteria are based on the [Open Source Security Foundation checks](https://scorecard.dev/#the-checks) for open-source repositories.
The checks are grouped into five categories: Code vulnerabilities, maintenance, continuous testing, source risk, and build risk.

## Code Vulnerabilities
### Vulnerabilities
Open vulnerabilities can be easily exploited by attackers and need to be addressed promptly. This check assesses if the project contains open, unresolved vulnerabilities in its codebase or dependencies. 

For the purpose of assessing open vulnerabilities for OpenStack components, the OSV (Open Source Vulnerabilities) service can be used. A further possibility is to generate SBOMs and analyze them, using existing tooling.

### Maintenance
#### Dependency Update Tool
The OSSF dependency update tool check tries to determine if the project uses a dependency update tool, for example Dependabot or Renovate bot.

#### Maintained
An inactive project may not receive patches, have its dependencies updated, or be actively tested and used. Some software, particularly smaller utility functions, typically doesn't require ongoing maintenance. However, OpenStack components can be expected to be actively maintained.

The _Maintained_ check assesses whether the project is actively maintained. In the OSSF check, an archived project receives the lowest score, while a project with at least one commit per week over the last 90 days earns the highest score. If there is activity on issues from collaborators, members, or owners, the project receives a partial score.

#### Security-Policy
This check tries to determine if the project has published a security policy. It works by looking for a file named SECURITY.md (case-insensitive) in a few well-known directories.

A security policy (typically a SECURITY.md file) can give users information about what constitutes a vulnerability and how to report one securely so that information about a bug is not publicly visible.

This check examines the contents of the security policy file awarding points for those policies that express vulnerability process(es), disclosure timelines, and have links (e.g., URL(s) and email(s)) to support users.

#### License
A license provides users with details on how the source code can or cannot be used. The absence of a license hinders any security review or audit and poses a legal risk for potential users.
This check therefore aims to identify if the project has a published license. It operates by utilizing hosting APIs or by examining standard locations for a file named according to common licensing conventions. 

According to OSSF, the license should be declared as follows:
- There should be a LICENSE, COPYRIGHT, or COPYING filename, or license files in a LICENSES directory
- The license file should be at the top-level directory
- A FSF or OSI license should be specified

In OpenStack projects, these files are contained in the opendev repositories.

#### CII Best Practices
This check evaluates if the project has achieved an OpenSSF Best Practices Badge at the passing, silver, or gold level. This badge signifies the project's adherence to a set of security-focused best development practices for open-source software. The automatic evaluation utilizes the Git repository URL along with the OpenSSF Best Practices badge API. 

### Continuous Testing
#### CI Tests
Executing tests allows developers to identify errors at an early stage, which can reduce the number of vulnerabilities that enter a project. This check therefore aims to verify whether tests are executed prior to merging pull requests. 

#### Fuzzing
Fuzzing involves inputting unexpected or random data into a program to uncover bugs. Conducting regular fuzzing is crucial for identifying vulnerabilities that could be exploited, particularly since attackers may utilize fuzzing to discover the same issues.

#### SAST
SAST is testing performed on source code prior to executing the application. Utilizing SAST tools can help prevent known types of bugs from being unintentionally introduced into the codebase.

### Source Risk Assessment
#### Binary Artifacts
The project repository should be free of executable binary artifacts (e.g. for Python `.pyc` files). Binary artifacts can not be easily reviewed, especially if the corresponding source code is not available.

#### Branch Protection
Branches, especially the main project branches (e.g. `main or master`, `release`), should be protected such that a defined workflow pattern for applying changes is enforced. This is necessary to prevent malicious code changes.
Potential checks (OSSF groups these in different tiers) include:
* prevent force push
* prevent branch deletion
* require PRs for code changes
* amount of necessary reviewer approvals before merging code
* code owner review necessary
* require branch to be up to date before pushing
* require approval of the most recent reviewable push
* require automated checks for approval

#### Dangerous Workflow
Test for dangerous patterns in CI/CD scripts. Vulnerabilities in such scripts may lead to repository compromise,
leakage of secrets and remote code execution.

Examples:
* untrusted code checkouts
* script injection via untrusted context variables

#### Code Review
Check whether code changes are reviewed by **humans** before they are added to the repository. Code reviews
are crucial to ensure the quality of code and to prevent potential vulnerabilities or malicious code injections 
in the first place.

#### Contributors
Check whether project has contributors from different organizations. Knowledge about contributing organizations
may help in deciding whether a project is trustworthy or not.

### Build Risk Assessment
#### Pinned Dependencies
The project should explicitly pin dependencies used for builds and releases not only by version but also with a
dedicated hash. Thereby it is ensured that always the same software is used enhancing reproducibility. This also 
mitigates the risk that new vulnerabilities are introduced by automatic updates or malicious package 
repositories. 

#### Token Permissions
Check if tokens used in workflow-pipelines follows the principle of least privilege. For example, a pipeline 
performing only automated tests on the repository code just requires read-only access to the repository content. 
Therefore, even if an attacker is able to compromise the pipeline-code, he is still not able to alter the 
repository content.

#### Packaging
Check whether the project publishes packages. Packages make it easier for customers to install and use the latest 
version as well as receiving security critical patches.

#### Signed Releases
Official project artifacts like packages should be accompanied with a cryptographic signature. This allows a user 
to verify the provenance of artifacts as well as their integrity. This is crucial in order to establish trust 
into such artifacts.

## Example Analysis
### Maintenance

#### Dependency Update Tool
[A central list of all the requirements](https://docs.openstack.org/project-team-guide/dependency-management.html) that are allowed in OpenStack projects is globally maintained. The OpenStack [proposal bot](https://review.opendev.org/q/owner:proposal-bot) automatically proposes updates to OpenStack dependencies and the proposals follow a defined workflow with reviews that verify that the proposed updates can be integrated.

OpenStack (Core) projects therefore fulfill the Dependency Update Tool criterion at the time of writing.

#### Maintained
There is a [list of designations for OpenStack projects](https://wiki.openstack.org/wiki/ProjectTypes) as follows:
- Core: official projects with full access to OpenStack brand and assets
- Incubated: projects that have been approved for the Incubator program which puts them on an official track to become core projects
- Library: library projects are directly or indirectly used by the core projects
- Gating: gating projects are used in the continuous integration processes, for example as integration test suites and specific deployment tools
- Supporting: supporting projects are used for, e.g., documentation and development infrastructure
- Related: related projects are unofficial projects are somehow associated with OpenStack but are not officially tied to OpenStack

The projects that can be considered to strictly follow the OpenStack security guidelines are thus the Core projects. Still, other projects are also actively maintained. The OSSF Maintained check defines a threshold of a maximum of 90 days for the last maintenance activity. A look at the list of OpenStack components on opendev.org, sorting them by _oldest_, [shows that all OpenStack components have been updated within the last day](https://opendev.org/openstack?q=&sort=oldest), fulfilling the Maintained check. 

OpenStack (Core) projects therefore fulfill the Maintained criterion at the time of writing.

#### Security-Policy
The requirements for the Security-Policy check are as follows:

Linking Requirements (one or more):
- A valid form of an email address to contact for vulnerabilities
- A valid form of a http/https address to support vulnerability reporting

Free Form Text:
- Free form text is present in the security policy file which is beyond simply having a http/https address and/or email in the file
- The string length of any such links in the policy file do not count towards detecting free form text

Security Policy Specific Text:
- Specific text providing basic or general information about vulnerability and disclosure practices, expectations, and/or timelines
- Text should include a total of 2 or more hits which match (case-insensitive) vuln and as in "Vulnerability" or "vulnerabilities"; disclos as "Disclosure" or "disclose"; and numbers which convey expectations of times, e.g., 30 days or 90 days

OpenStack has a vulnerability management team [with four members](https://security.openstack.org/vmt.html) and a documented [Vulnerability Management Process](https://security.openstack.org/vmt-process.html). Email addresses to contact in relation to vulnerabilities are published on the respective web pages.
The Free Form Text criterion as well as the Security Policy Specific Text criterion are thus also fulfilled by the OpenStack [Vulnerability Management Process](https://security.openstack.org/vmt-process.html) (VMP). The VMP also defines time periods, for example for the disclosure to downstream stakeholders. However, to the best of the authors' knowledge, no time frame is defined for the patch development and review.

OpenStack (Core) projects therefore fulfill the Security-Policy check at the time of writing.

#### License
OpenStack components are published under the Apache 2.0 license which can be found in the LICENSE file in each repository, see, for example, https://opendev.org/openstack/nova/src/branch/master/LICENSE.
The criteria listed above are all fulfilled for OpenStack components.

OpenStack (Core) projects therefore fulfill the License check at the time of writing.

#### CII Best Practices
OpenStack [has the _passing_ badge](https://www.bestpractices.dev/de/projects?q=openstack), which is the lowest of three levels. Some of the criteria that are not fulfilled for the silver and gold badges, [include the following](https://www.bestpractices.dev/de/projects/246?criteria_level=2):
- The project website, the repository, and the downloaded pages (if separate) MUST include key-hardening headers with non-permeable values
- The project MUST apply at least one dynamic analysis tool to each upcoming major production release of the software produced by the project before its release.

**Some criteria are not clearly documented, e.g. _The project SHOULD support multiple cryptographic algorithms so that users can quickly switch if one is compromised. Common symmetric key algorithms include AES, Twofish, and Serpent. Common cryptographic hash algorithm alternatives include SHA-2 (including SHA-224, SHA-256, SHA-384, and SHA-512) and SHA-3._ These can be investigated in more detail in the following iterations of the project.**

### Continuous Testing
#### CI Tests
OpenStack projects use [Zuul](https://zuul-ci.org/). Also, the OpenStack documentation gives insight into the [testing procedures](https://docs.openstack.org/project-team-guide/testing.html).
Zuul results can be reviewed on [opensearch](https://opensearch.logs.openstack.org/_dashboards/app/discover?security_tenant=global) with the credentials openstack/openstack. One can filter results, e.g., for failed builds or visualize charts about the ratio of success and failures.

Note also that a consistent [testing interface](https://governance.openstack.org/tc/reference/project-testing-interface.html) has been defined across OpenStack projects and common requirements for testing are defined.

OpenStack (Core) projects therefore fulfill the CI Tests check at the time of writing.

#### Fuzzing
Formerly, there was an OpenStack fuzzing tool called [Syntribos](https://github.com/openstack-archive/syntribos), which is now archived. CI files (such as the [Nova CI file](https://opendev.org/openstack/nova/src/branch/master/.zuul.yaml)) do not indicate a standard usage of fuzzing tools in pipeline. Also, the [security guide](https://docs.openstack.org/security-guide/) does not mention fuzzing tools. 
In OpenStack components, the Tox automation tool is used to run different types of tests. The ```tox.ini``` files in the components' repositories, however, do not contain references to fuzzing tools. At the time of writing, it is thus assumed that security reviewers can, but are not forced to, use fuzzing tools in their reviews.

#### SAST
The [OpenStack documentation](https://docs.openstack.org/security-guide/compliance/compliance-activities.html) mentions code analysis, penetration testing, and other approaches for security reviews, but does not clearly stipulates their usage. [Bandit](https://wiki.openstack.org/wiki/Security/Projects/Bandit) is a Python SAST tool that was originally developed in OpenStack, but is now independent. The ```tox.ini``` files in the components' repositories show which SAST and other tooling is applied. Nova's tox file, for example [includes the usage of Bandit](https://github.com/openstack/nova/blob/master/tox.ini#L275). Also Cinder and Barbican include Bandit testing.
It is unclear, however, if it is mandatory to include SAST tools in the testing of OpenStack components.

### Vulnerabilities
#### Code Vulnerabilities
The OSV (Open Source Vulnerabilities) service allows to review vulnerabilities in open-source projects. A [search for openstack vulnerabilities](https://osv.dev/list?q=OpenStack&ecosystem=) results in various potential vulnerabilities in different OpenStack-related packages.
For severe security issues, OpenStack security advisories (OSSAs) are published. In 2024, five such OSSAs have been published.

### Source Risk Assessment
#### Binary artifacts
The repository of Openstack nova contains no binary artifacts. (OSSF tool applied on github mirror of nova).

#### Branch Protection
Open issues: Verification that official workflow can not be easily bypassed (e.g. missing api restrictions).

Opendev Gerrit-Workflow ensures the following aspects:
* Code must be approved by at least one core-reviewer
* Code must pass automated gate tests
* code must pass automated testcases
* if all conditions are met code gets automatically merged

This corresponds to tier 4 according to ossf defintions.

#### Dangerous Workflow
Openstack uses the opendev infrastucture for code hosting and building. Thereby openstack components heavily rely on Zuul as
CI/CD framework (s. [opendev workflow](https://docs.opendev.org/opendev/infra-manual/latest/gettingstarted.html#the-opendev-workflow)). OSSF scorecard currently has not build in support for Zuul-related configuration files. Therefore further analysis of Zuul configuration files and pipeline syntax is necessary.

#### Code Review
Code changes need to be reported using Gerrit. Once visible, everyone is allowed to review the changes and provide feedback 
via a voting system. Only core-reviewers are allowed to give a `+2` vote which is mandatory for approving changes. Per
Openstack convention, at least two independent core-reviewers must provide such a vote in order to approve code changes for merging. Furthermore, before being merged code changes need to pass several test-pipelines. Merging is performed automatically using Zuul.

#### Contributors
Applying OSSF scorecards on the Github mirror of openstack-nova revealed a total of 47 different contributing organizations.
Amongst them RedHat, Nvidia and IBM.

### Build Risk Assessment
#### Pinned Dependencies
Applying OSSF scorecards on the Github mirror of openstack nova, no pinned dependencies have been found.
A `requirements.txt` exits ([link](https://github.com/openstack/nova/blob/master/requirements.txt)), but only a minimum 
version number is defined for each dependency. Furthermore, it is stateted in a comment that these lower bounds are only 
kept up to date on a best effort basis. For passing the check, explicit hashes of the used versions would be necessary (see [PIP doc on secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/#secure-installs)).

#### Token Permissions
OSSF scorecard currently is not capable of analysing Zuul related configuration files. Further investigation of the Zuul framework and its integration in opendev is necessary for understanding necessary access privileges. This is necessary in order to allow assessing whether pipeline scripts of a openstack component follow the principle of least privilege.

#### Packaging
Opendev supports automatic publishing of releases on [PyPI](https://docs.opendev.org/opendev/infra-manual/latest/creators.html#give-opendev-permission-to-publish-releases).

#### Signed Releases
[Releases seem to be signed](https://tarballs.opendev.org/openstack/nova/). Nevertheless, the signature is not visible on 
https://releases.openstack.org/dalmatian/index.html#nova as well as on [PyPI](https://pypi.org/project/nova/).