# User Guide

## Target Audience

This guideline targets the roles of the OpenStack Checker expert, evaluator or product expert, and any other person who aims to write custom rules for the OpenStack Checker or "tag" a program with concepts and operations.

We expect the target audience to have average programming skills and extensive security knowledge.

## General Setup

Do develop the project using IntelliJ IDEA.
Starting with version 2025.1, IntelliJ comes with support for kotlin script files.
To profit from this feature, it is, however, necessary to configure the IDE accordingly once.
In the settings, please search for "Languages & Frameworks -> Kotlin -> Kotlin Scripts" and click "Scan Classpath".
This will add the .query.kts and .concept.kts files and you will get syntax highlighting and code completion for them.

## Contents

The following chapters are currently available:

* [How to analyze a project](analyzing-project.md),
* [How to write queries](writing-queries.md),
* [How to interpret the results](understanding-results.md),
* [Information on implementing concepts and operations and how they are linked to the code](concepts-and-operations.md),
* [A list of concepts and operations](list-concepts-and-operations.md),
* [A concept for categorizing assumptions of the analysis](assumptions-concept.md),
* [The tradeoff between assumptions and manual analysis](assumptions-tradeoff.md), and
* [A list of further resources](more-resources.md).

