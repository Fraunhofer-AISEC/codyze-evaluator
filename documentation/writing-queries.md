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

## The security goals yaml

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

## Writing the security statements in the `query.kts` file

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

### Hints on writing queries

**Handling of `null` values:**

Kotlin differentiates between `null` and non-null values. To work with nullable values, use the `?` syntax/operator and
implement checks using the `?.let` or `?:` operator rather than enforcing non-null values with `!!`. This ensures that
all your queries will be evaluated even in the presence of null-values whereas using `!!` would immediately crash the
execution. Keep in mind that the missing information in the check should likely result in a warning, which means you
probably want to generate a failing result in this case (e.g. by creating a `QueryTree(false, ...)`).

**Using variables:**

Some data are likely to change frequently. Rather than hardcoding this information in the queries, you can use a
variable. This makes it easier to update the information in subsequent usages of the same security statement or
objectives.

**Using extensions:**

To keep the actual query small, we recommend getting familiar
with [Kotlin Extensions](https://kotlinlang.org/docs/extensions.html) which can be used to extend existing classes with
new functionality without having to inherit from the class. They can be used to add functions or properties.