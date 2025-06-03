# User Guide

## Target Audience

This guideline targets the roles of the OpenStack Checker expert, evaluator or product expert, and any other person who aims to write custom rules for the OpenStack Checker or "tag" a program with concepts and operations.

We expect the target audience to have average programming skills and extensive security knowledge.

## General Setup

We develop the project using IntelliJ IDEA.
Starting with version 2025.1, IntelliJ comes with support for kotlin script files.
To profit from this feature, it is, however, necessary to configure the IDE accordingly once.
It is recommended to compile the project first using `./gradlew build` so that all classes are available in the IDE.
In the settings, please search for "Languages & Frameworks -> Kotlin -> Kotlin Scripts" and click "Scan Classpath".
This will add the `.codyze.kts` files, and you will get syntax highlighting and code completion for them.

### Known Bugs

**(New) Queries from the Catalog are shown as unresolved in .codyze.kts**

In order to update the IDE cache after new queries have been added to the `codyze-query-catalog` or specific evaluation project, it might also be necessary to first build the project and then click on "Scan Classpath" again.

**Sources of Queries are not available**

Sometimes, IntelliJ has difficulties finding the source files of the queries. For queries or concepts contained in the `codyze-query-catalog` it might be necessary to manually click on "Choose Sources" after click on a symbol and then choosing the folder `codyze-query-catalog/src/main/kotlin`.
Similarly, if a query or concept is defined directly in the evaluation project (as shown in the `evaluate-hardened-openstack` example project), "Choose Sources" must be chosen and the `src/main/kotlin` folder of the (example) evaluation project must be selected.

## Contents

The following chapters are currently available:

* [How to analyze a project](analyzing-project.md),
* [How to write queries](writing-queries.md),
* [Basics of Program Analysis and its Application in the Query API](program-analysis-basics.md),
* [Hints on Kotlin for Writing Sleek Queries](kotlin-for-queries.md),
* [Information on implementing concepts and operations and how they are linked to the code](concepts-and-operations.md),
* [A list of concepts and operations](list-concepts-and-operations.md),
* [A description of the Tagging DSL](tagging-dsl.md),
* [A concept for categorizing assumptions of the analysis](assumptions-concept.md),
* [The tradeoff between assumptions and manual analysis](assumptions-tradeoff.md),
* [Some Examples](examples.md),
* [How to interpret the results](understanding-results.md),
* [How to provide negative test results](negative-tests.md), and
* [A list of further resources](more-resources.md).

