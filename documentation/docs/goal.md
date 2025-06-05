# Goal of the Codyze Evaluator

The Codyze Evaluator provides tooling and guidelines to assess the security of a generic software product, in the following called TOE.

It can be used in different technology-dependent profiles, where the OpenStack-specific profile considers two major aspects:

* The compliance of the TOE's (in this case OpenStack) code base and a specific configuration with respect to security claims, and
* The ecosystem of OpenStack and its development workflow.

## Compliance with Security Claims

Core of this project is a tool which supports an analyst with a semi-automated compliance checks of a specific instance of the TOE.

It receives as an input:

* A set of rules which define the security claims to be evaluated,
* A set of relevant behavioral properties (in the form of so-called concepts and operations) and logic on how to tag the code base with them, and
* The TOE's code base, python interface (.pyi) files of libraries, and a specific configuration of the TOE's instance.

The tool then performs a static analysis of the code base and configuration and generates a report which indicates whether the security claims are met or not.

The following figure provides a high-level overview of the workflow on the example of OpenStack:

![Workflow](assets/img/highlevel-overview.png)

A detailed description of the methodology, and the core components of the Codyze Evaluator and its configuration is provided in the section [Methodology](methodology.md).

The [User Guide](user-guide.md) provides a detailed description of the tool and its usage and should enable the human actor to write the respective Codyze Evaluator configuration.

## Ecosystem of OpenStack

The analysis of the ecosystem considers security-critical aspects which are not directly visible in the code base of the OpenStack components or their configuration by a cloud provider.
This is complementary to the analysis of the code base and configuration and considering it may serve to ease early detection of problems in the development workflow which can later have an impact on the security of the product.
These include various aspects which are related to the development workflow of OpenStack, such as the use of third-party libraries, the use of CI/CD pipelines and automated checks performed therein, and which parties are involved in the development of OpenStack.

The complete documentation on the analysis of OpenStack's ecosystem is provided in the [Ecosystem Analysis](ecosystem-analysis.md) section.
