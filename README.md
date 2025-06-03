# Codyze Evaluator

This is a specialized version of Codyze that supports security evaluators, for example in the process of conducting a CC-based security evaluation.

## Requirements - Python JEP
This project uses the [CPG](https://github.com/Fraunhofer-AISEC/cpg) and
therefore requires [JEP](https://github.com/ninia/jep/) to analyze Python code.
See the [CPG documentation](https://github.com/Fraunhofer-AISEC/cpg/?tab=readme-ov-file#python)
for information on how to configure JEP.

## Project structure

The project is structured as follows:
- `codyze-evaluator`: Contains the main code for the Codyze Evaluator.
- `codyze-query-catalog`: Contains a set of queries that can be used to evaluate security requirements in code.
- `technologies`: Contains technology-specific passes.
  - `codyze-openstack`: Contains passes for the OpenStack technology.
  - ...
- `examples`: Contains example projects that show-case how to use the Codyze Evaluator in a security evaluation process.
  - `evaluate-hardened-openstack`: An example evaluation of OpenStack with the Codyze Evaluator.
  - ...
- `documentation`: Contains user-facing documentation for the Codyze Evaluator.

## Further documentation

A user facing documentation is available in the [`documentation`](documentation/docs/index.md) folder.

The page can be rendered with mkdocs and using docker as follows:
```bash
cd documentation
docker build -t mkdocs-material .
docker run --rm -it -p 8000:8000 -v ${PWD}:/docs mkdocs-material
```
