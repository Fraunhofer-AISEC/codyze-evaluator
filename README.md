# openstack-checker

This is a specialized version of Codyze that checks OpenStack.

## Requirements - Python JEP
This project uses the [CPG](https://github.com/Fraunhofer-AISEC/cpg) and
therefore requires [JEP](https://github.com/ninia/jep/) to analyze Python code.
See the [CPG documentation](https://github.com/Fraunhofer-AISEC/cpg/?tab=readme-ov-file#python)
for information on how to configure JEP.

## Project Structure

The openstack-checker currently houses two "projects":
- `BYOK`: An example of a Bring Your Own Key (BYOK) implementation in OpenStack. It currently includes one security goal for disk encryption.
- `magnum-cve`: An example with queries for general security goals like deleting secret data from memory and setting file permissions correctly.

Furthermore, the projects folder contains a "common" folder, which includes common security goals and requirements, which can be used by all projects. Currently, they need to be linked into the specific project, but in the future, all queries and goals in the common folder will also be considered.

To run it on the BYOK example (this might take a while):
```
git submodule update --init
./gradlew installDist
./app/build/install/app/bin/app --project-dir=projects/BYOK --components barbican --components castellan --components cinder --components conf --exclusion-patterns tests --exclusion-patterns drivers
```

To run it on the magnum-cve example:
```
git submodule update --init
./gradlew installDist
./app/build/install/app/bin/app --project-dir=projects/magnum-cve --components magnum --exclusion-patterns tests
```

## Web-UI

To see the results in the web-UI, run the app with the flag `--console=true`, e.g. as follows:

```
./app/build/install/app/bin/app --project-dir=projects/magnum-cve --components magnum --exclusion-patterns tests --console=true
```

The Web-UI should be accessible on http://localhost:8080.

## Development

We are using git submodules to include OpenStack repositories. To clone the submodules, use the following command:
```bash
git submodule update --init --remote
```

We are using development builds of CPG and Codyze, which are hosted in the GitHub Package Registry. In order to access them, a personal access token (PAT) is needed. You can create one using the following steps:
```bash
./configure-github.sh
```

## Further documentation

The documentation is available in the `documentation` folder. It contains further information on:

* [How to write queries](documentation/writing-queries.md), and
* [How to interpret the results](documentation/understanding-results.md)
