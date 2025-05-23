# How to analyze your project

The OpenStack Checker is a tool that helps you identify security issues in your OpenStack project by analyzing the code
and checking it against a set of predefined queries.
This document describes how to use the OpenStack Checker to analyze your project, how to structure an analysis project
and how to write those queries.

## Project structure

Currently, the OpenStack Checker requires a fixed project structure. It expects the following:

    .                                     # Project root
    ├── components                        # This directory contains the components of your project which should be analyzed.
        ├── component1                    # The first component of your project
        └── component2                    # The second component of your project
    ├── libraries                         # This directory contains the libraries which are used by your project but which are not the primary target of the analysis. They are integrated in the analysis if needed.
    ├── queries                           # The individual queries are structured in the `query.kts` files in this directory
        ├── security-objective1.query.kts # This files contains the queries for one of the security objectives. The filename must be the name of the objective but with dashes instead of whitespace and written in lowercase. File ending must be `query.kts`.
        └── security-objective2.query.kts # This files contains the queries for one of the security objectives. The filename must be the name of the objective but with dashes instead of whitespace and written in lowercase. File ending must be `query.kts`.
    ├── security-goals                    # In this directory, you can specify the security goals of your project in one or multiple yaml-file
        └── Your-Security-Goals.yaml      # This files contains a human-readable list of security objectives and statements

## Defining an analysis project

We provide a Domain-Specific Language (DSL) to define an analysis project.
This DSL is used to specify the components of the TOE (Target of Evaluation) and the requirements it has to satisfy.
It further allows to integrate the logic for tagging the code with concepts and operations, and to accept or reject assumptions.
In the following, we describe how to configure the analysis project using the DSL.

The outer element is the `project` element which has a `name` can contain the declarative blocks `tool`, `toe`, `requirements`, and `assumptions`.
```kotlin
project {
    name = "This is the evaluation of OpenStack"

    tool { ... }
  
    toe { ... }
  
    requirements { ... }
  
    assumptions { ... }
}
```

The `tool` block can be used to fine-tune the configuration of the OpenStack Checker by registering additional passes or external libraries, among others.
The full list of options can be found in the documentation of the `TranslationConfiguration.Builder` which can be accessed here.
An example of a `tool` block is:
```kotlin
tool {
    // Register additional passes
    registerPass<MyPass>()

    // Where can includes be found
    includePath("src/integrationTest/resources/example/src/third-party/mylib")

    // Should include be loaded?
    loadIncludes(true)
}
```

The `toe` block is used to specify the TOE and where its components can be found.
The information provided here are used to translate the TOE to the CPG.
The following example shows how to use this block:
```kotlin
toe {
    // The name of the TOE
    name = "My Mock TOE"
    // The architecture of the TOE in terms of different components
    architecture {
        // The list of each component/module
        modules {
            // The first module. The parameter specifies the name of the module.
            // The information provided here is used to configure the CPG translation.
            module("module1") {
                // The directory defines where the module's code can be found. 
                directory = "src/module1"
                // All files in this directory should be included in the analysis.
                includeAll()
                // We want to exclude the tests from the analysis. 
                exclude("tests")
            }
        }
    }
}
```

The `requirements` block is used to specify the requirements the TOE has to satisfy.
Each `requirement` listed here has a name and can be checked by automatically running a query, a manual assessment, or a combination of both.
The manual assessment is specified by using the `byManualAssessment` function which requires a unique identifier as a parameter.
The documentation of the check itself is not specified here but in another file.
The automatic assessment is specified by using the `byQuery` function runs a check on the `TranslationResult` and must return a `QueryTree<Boolean>` object.
```kotlin
requirements {
    // Each of the requirements has a name which is passed by the mandatory parameter.
        requirement("Is Security Target Correctly specified") {
            // The requirement is composed by exactly one statement.
            // In this case, we have to assess manually, if the requirement is satisfied, what is done by the `byManualAssessment` function.
            // This function must be configured with a unique identifier of the check to be performed.
            byManualAssessment("SEC-TARGET")
        }

        requirement("Good Encryption") {
            // This requirement is checked fully automatically by the query specified in the `byQuery` function.
            // The lambda receives the translation result as a parameter and must return a `QueryTree<Boolean>` object.
            // It uses the two helper functions `goodCryptoFunc` and `goodArgumentSize` which are part of the catalogue.
            byQuery { result -> goodCryptoFunc(result) and goodArgumentSize(result) }
        }
  
         requirement("Hybrid check") {
            // This requirement is checked by a hybrid approach. The first part is checked by the query specified in the `byQuery` function.
            // The second part is checked manually by the `byManualAssessment` function.
            // Both parts are combined by the `and` operator which returns a QueryTree<Boolean>.
            byQuery { result -> query(result) } and  byManualAssessment("HYBRID")
         }
    }
```
The block `assumptions` is used to specify the assumptions which have to hold so that the analysis is meaningful.
It also allows to specify the state of the assumption (i.e., accepted, rejected, ignored or undecided).
To do so, the functions `accept`, `reject`, `ignore` and `undecided` can be called with the UUID of the respective assumption.
To list more assumptions for documentation purposes, the function `assumption` can be used.
Note that this assumption does not have to be accepted manually and won't be included in the analysis or translation result.
```kotlin
assumptions {
    // Documentation of an additional assumption which has to hold and is accepted.
    assume { "We assume that everything is fine." }
    // Accept the assumption with the UUID "00000000-0000-0000-0000-000000000000" which is part of the CPG or the queries.
    accept("00000000-0000-0000-0000-000000000000")
    // Reject the assumption with the UUID "00000000-0000-0000-0000-000000000001" which is part of the CPG or the queries. 
    reject("00000000-0000-0000-0000-000000000001")
    // Nobody has decided on the assumption with the UUID "00000000-0000-0000-0000-000000000002" which is part of the CPG or the queries.
    undecided("00000000-0000-0000-0000-000000000002")
    // Ignore the assumption with the UUID "00000000-0000-0000-0000-000000000003" which is part of the CPG or the queries.
    ignore("00000000-0000-0000-0000-000000000003")
}
```

## Legacy: The security goals yaml

This file contains a human-readable list of security objectives and statements. The file is structured in a way that
each security goal is a top-level entry, and each security goal can have multiple components, assumptions, and
objectives.

It has to comply with the following structure:

```yml
name: This field describes the name of your analysis project
description: Provides a short description
components: # This will typically be the same as the directory `components`
  - component1
  - component2
assumptions: # This list can be used to note down some generic assumptions which have to hold so that the analysis is meaningful
  - assumption 1
  - assumption 2
objectives: # This is the list of security objectives which are relevant for your project. It has to be in-line with the filenames in the `queries` directory
  - name: Security Objective1
    description: This provides a high-level human-readable description of the objective.
    statements:
      - This is a human-readable description of a security statement. One query has to be written in the respective query.kts file.
      - This is another human-readable description of a security statement. One query has to be written in the respective query.kts file.
    components: # A list of the affected components.
      - cinder
  - name: Security Objective2
    description: This provides a high-level human-readable description of the objective.
    statements:
      - This is a human-readable description of a security statement. One query has to be written in the respective query.kts file.
      - This is another human-readable description of a security statement. One query has to be written in the respective query.kts file.
    components: # A list of the affected components.
      - cinder
```

## Legacy: Writing the security statements in the `query.kts` file

The `query.kts` file represents a single security objective.
It contains one function for each statement belonging to this objective. This function expects a `TranslationResult` as
an input and must return a `QueryTree<Boolean>` object.
The function representing the statement is simply called `statementN`, where `N` is the number/counter of the statement.
This leads to the following "signature":

```kotlin
fun statement1(translationResult: TranslationResult): QueryTree<Boolean> {
    // The implementation of the query
}
```

Besides one such function per statement of the respective objective, it is possible to write any kotlin code in this
file which will later be executed.
This can be used to define helper functions or easily configurable variables which are needed for the implementation of
the queries or which may be useful to keep the queries' code cleaner and easier to read and adapt.

To write those queries, you should be familiar with the Kotlin programming language and the CPG's structure and Query
API.
A set of initial resources could be:

* [Documentation of the Query API](https://fraunhofer-aisec.github.io/cpg/GettingStarted/query/). Note that you have to
  use the "extended" version here
* [The CPG's shortcuts](https://fraunhofer-aisec.github.io/cpg/GettingStarted/shortcuts/). These can be useful to
  quickly access interesting properties of the program under test.
* [The Kotlin Language Documentation](https://kotlinlang.org/docs/home.html). This is the official documentation of the
  Kotlin programming language. It lists all features of the language with various examples. The section "Concepts"
  should be the most relevant one.

The files [list-concepts-and-operations.md](list-concepts-and-operations.md), [writing-queries.md](writing-queries.md), and [more-resources.md](more-resources.md) provide further documentation on existing concepts and operations, writing queries with the Query API, and point to additional resources.