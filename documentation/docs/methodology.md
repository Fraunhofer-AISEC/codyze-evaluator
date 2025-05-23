# Methodology

This chapter describes the methodology which we use to assess the compliance of an OpenStack instance with respect to security goals.
The high-level architecture and workflow is presented in the chapter [Goals](goal.md), but we provide a short recap here:

![Workflow](assets/img/highlevel-overview.png)

As the overview of the workflow shows, the OpenStack Checker consists of two major inputs:

* The *Concrete OpenStack Instance* is the Target of Evaluation (TOE).
  It consists of various components of OpenStack at a certain software version, several third party libraries (i.e., python libraries) and a specific configuration of the whole system.
  The TOE implements the security claims by its *security features*.
* The *OpenStack Checker Configuration* is the configuration of the OpenStack Checker.
  It consists of a set of security goals, a set of concepts and operations, and a set of rules which define how to "tag" the code base with these concepts and operations.

!!! note "Relation to Common Criteria Evaluation"

    To retrieve the OpenStack Checker Configuration, the evaluator can exploit the following resources:

    * The Protection Profile to which the TOE claims compliance.
    * The Security Target of the TOE, in particular the Security Functional Requirements (SFRs) and the details on their implementation.

## OpenStack Checker: Compliance Checking Tool

Internally, the OpenStack Checker translates the TOE to a [Code Property Graph (CPG)](https://github.com/Fraunhofer-AISEC/cpg) and uses this representation for subsequent static analysis of the TOE.
The OpenStack Checker Configuration follows two goals: First, it adds semantic information to the program code and second, it queries the CPG to evaluate if the security goals are met.
As the implemented static analyses can introduce false positive and false negative findings, the CPG aims to explicitly state *assumptions*  which are made during the translation and analysis.
These can be introduced by general assumptions and limitations of static analysis tools, ambiguous and unclear language features, missing implementation details, imprecise or unsound analysis methods, or heuristics used for certain tasks.

This section describes

* the CPG as representation of source code,
* how we integrate the configuration of the TOE,
* the CPG's extension to model program semantics, and
* the meaning of assumptions in the context of the analysis

### The Code Property Graph (CPG) as Source Code Representation

Internally, the OpenStack Checker translates the TOE's code base and configuration to a [Code Property Graph (CPG)](https://github.com/Fraunhofer-AISEC/cpg).
This is a graph representation abstracting from different programming languages, and including various information which are required for static code analysis.
In particular, it includes the following sub-graphs:

* The evaluation order graph (EOG) determines the order in which statements and expressions may be traversed at run-time
* The dataflow graph (DFG) summarizes data dependencies between different statements and expressions
* The call graph (CG) contains the function calls and possible call targets
* The control dependence graph (CDG) summarizes if reaching a statement depends on the evaluation of a certain condition
* The program dependence graph (PDG) combines the CDG and DFG

Furthermore, it resolves the type hierarchy containing the inheritance relations between classes and interfaces, types of expressions, and references and usages between variables and expressions.

For a complete overview of the CPG's implementation details, we refer to the documentation of the CPG library[^1].

To provide an abstraction from the programming language, the nodes and edges of the CPG include information about specific programming language features.
Examples for this are that the EOG may differ for similar operations depending on the language, or types with the same name have different properties, e.g. when considering mutable vs. immutable types, the size of numeric types, or signed vs. unsigned numbers.
Prior research[^2] has shown that this representation minimizes the loss while still providing an abstract interface for subsequent analyses.

The CPG library used in the OpenStack Checker supports python as programming language, which is used for developing the OpenStack components.

Each component of OpenStack is kept in a separate `Component` inside the CPG.
This simulates that they do not share they are separate projects but can communicate via specific interfaces (in the case of OpenStack, these are HTTP calls).

### Integration of the Configuration

Besides the code base, the OpenStack Checker also considers the configuration of the TOE.
OpenStack is configured via .ini files, which is why the CPG library had been extended with a custom language-frontend parsing these files.
The configuration is then represented in the CPG in a separate `Component` which holds the hierarchy of the sections in the ini files, as well as the key-value pairs.
Custom `Pass`es connect the usage of configurations within the source code of OpenStack components with the values held in the configuration.

### Modelling Semantics via `Concept`s and `Operation`s

While the CPG provides a representation of the source code's syntax, it does not provide any semantic information nor an abstraction thereof.
As most requirements, however, are not directly related to the syntax of the code but rather to its semantics, enriching the CPG with semantic information can greatly generalize queries checking for certain requirements.
To enable this, we extended the CPG with so-called `Concept`s and `Operation`s. These model semantic information, either in a general way (`Concept`) or by abstracting a specific behavior/action of the source code (`Operation`).
The `Concept`s and `Operation`s are added to the CPG as nodes, which are, however, not part of the existing source code (we use the term `OverlayNode` for this) and are connected to the existing nodes of the CPG via specific edges (`overlayEdges` and `underlyingNode`), as well as the EOG and DFG.

The `Concept`s and `Operation`s are defined in the module `cpg-concepts` but, as this list is not complete for all cases (i.e., any analysis can require additional semantic information), it is possible to extend these via the OpenStack Checker configuration.
The mapping of source code to the semantic information can be implemented as custom passes or as part of the OpenStack Checker configuration via a specific domain specific language (DSL).

!!! info "Connecting different OpenStack components"

    As different OpenStack components interact with each other via HTTP calls, we provide passes identifying the HTTP endpoints and calls thereof.
    Another pass (`HttpEndpointsBindingPass`) connect the HTTP calls with the respective endpoints.

    The endpoints can be identified based on the libraries Pecan and Wsgi, which are used in OpenStack.

!!! info "Configuration of the TOE"

    For the configuration of the TOE, we also provide specific passes which model the values of the .ini files as `Concept`s and `Operation`s to simplify the identification thereof when mapping it to the source code.

!!! info "Dynamic Loading of OpenStack's Features"

    OpenStack has been developed with extensability in mind.
    While this is a great feature, it significantly complicates the static analysis of the code base.
    The heavy usage of dynamic loading of additioal features and drivers through the custom library Stevedore makes it hard to statically analyze the code base and follow the flow through the program.
    In particular, many security critical features and their integration depend on the configuration which is used to determine which drivers are loaded.

    To address this, we provide a pass which connects the dynamic loading of drivers with the respective configuration and loads/instantiates additional modules and connects their functions according to the provided configuration.

### Explicitly Stating Assumptions

Just as any other analysis tool, the OpenStack Checker may introduce false positive and false negative findings.
This can originate from errors in the implementation of the OpenStack Checker (and the underlying CPG library), general limitations of the static analysis methods used, imprecision when tagging concepts and operations, unsupported features, ambiguous code snippets, or failing heuristics.

To address this, we explicitly which assumptions have been made during the analysis or have to be accepted to rely on the results of the OpenStack checker.
While some assumptions have to hold on a global level (e.g., no bugs in the implementation of the OpenStack Checker exist, the run of the OpenStack Checker was not compromised, ...), other assumptions (e.g., related to the correctness of certain translation on ambiguous code, known incomplete code, usage of heuristics) are specific to certain patterns in the TOE's code.
These are generated while constructing the CPG (in frontends, passes and the tagging logic) and are directly integrated into the CPG and linked to the node or edge which is affected by the assumption.

When querying the CPG, the assumptions which may affect the result (i.e., they are located on a path which is traversed) are returned as part of the result of the query.

Assumptions which are specific to an analysis method used to query the CPG and run the compliance checks, are not added to the CPG but still returned in the result of a query. 

This provides a human evaluator with a good understanding of the limitations of the analysis and the assumptions which have to be accepted to rely on the results.
More importantly, the evaluator can perform a targeted assessment if the assumptions are valid for the given TOE or if they can be accepted (depending on the EAL of the evaluation, some assumptions may simply not be relevant) and thus increase the trust into the OpenStack Checkers results.

Accepting assumptions are fed into subsequent runs of the OpenStack Checker, so that they are not considered again and ultimately, a reproducible and understandable evaluation can be achieved.
If an assumption cannot be accepted, the respective finding requires manual re-evaluation.

### Running the Compliance Checks as Queries

The security claims of the TOE are expressed in the form of queries, which are executed on the CPG.
Then, it traverses the CPG and collects information about the nodes and edges which are relevant for the analysis.
An extensive guideline on how to write queries is provided in the chapter [How to write queries](writing-queries.md).

In short, a Query can access all information held in the CPG and is typically structured as follows:
"for all nodes X in the graph, the property Y must hold" or "there must be at least one node X in the graph, for which the property Y holds".

To identify X, the nodes in the CPG are traversed and filtered based on their type and optional pre-conditions provided in the query.

The property Y is the actual requirement and can be deducted from a PP, SFR, best practices in coding, certain requirements of a specific implementation (e.g. library) or other sources of security goals.
Frequent properties are a specific configuration of concepts and operations, or requirements on data flows and mandatory actions on each path in the execution.
To simplify such queries, the CPG provides a set of methods to traverse the graph and perform reachability analyses.

The result of each query is a verdict if it holds together with a list of all steps which have been conducted to reach to this conclusion, as well as the assumptions which have to be accepted.

## User Roles and Skills

As there is a human involved in the workflow, we need to define the roles and skills of the human actor(s).
We currently consider the following roles:

* An *OpenStack Checker Expert* is a person with extensive knowledge on the OpenStack Checker and its configuration.
  This person is able to write the OpenStack Checker configuration and to interpret the results of the analysis.
  The OpenStack Checker expert may also be involved in the development of new queries and security goals.
  The OpenStack Checker expert may write custom Passes which enrich the CPG or could extend the Query API and provide novel analyses.
* A *Domain Expert* is a person with extensive knowledge in a certain domain, e.g., cryptography, or hardware-based security mechanisms.
  The domain expert is responsible to specify requirements in the respective domain on a technical level but may not be able to write the rules for the OpenStack Checker.
  The domain expert is also able to assess whether some findings of the OpenStack checkers are valid and can validate or refute the findings and their underlying assumptions.
* An *Evaluator* is a person with extensive knowledge in the field of security evaluation and leads and supervises the evaluation.
  The evaluator may delegate technical assessments to the domain expert and customizing/configuring the OpenStack Checker according to the requirements to the OpenStack Checker Expert.
  However, the evaluator should be able to interpret the results of the OpenStack Checker and write simple queries.
  The evaluator is responsible to assess the compliance of the OpenStack instance with respect to the security goals and claims.
* A *Product Expert* is a person with extensive knowledge of the concrete OpenStack instance spanning its components and configuration.
  The product expert should be able to point out implementation details of the TOE and describe how they relate to the security goals.
  The product expert may also be involved in the development of new queries and tagging the code with semantic concepts and operations.

  
[^1]: https://fraunhofer-aisec.github.io/cpg/CPG/specs/
[^2]: Yamaguchi, Fabian, et al. "Modeling and discovering vulnerabilities with code property graphs." 2014 IEEE Symposium on Security and Privacy (S&P). IEEE, 2014.