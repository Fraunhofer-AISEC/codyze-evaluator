# openstack-checker

This is a specialized version of Codyze that checks OpenStack.

## Requirements - Python JEP
This project uses the [CPG](https://github.com/Fraunhofer-AISEC/cpg) and
therefore requires [JEP](https://github.com/ninia/jep/) to analyze Python code.
See the [CPG documentation](https://github.com/Fraunhofer-AISEC/cpg/?tab=readme-ov-file#python)
for information on how to configure JEP.

## Project Structure

The openstack-checker currently houses two "projects":
- `small-example`: A small example that demonstrates the checker's capabilities.
- `BYOK`: An example of a Bring Your Own Key (BYOK) implementation in OpenStack. It currently includes one security goal for disk encryption

To run the checker on the small example:
```
./gradlew installDist
./app/build/install/app/bin/app --project-dir=projects/small-example --sources projects/small-example/ssl_version.py 
```

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

## Development

We are using git submodules to include OpenStack repositories. To clone the submodules, use the following command:
```bash
git submodule update --init --remote
```

We are using development builds of CPG and Codyze, which are hosted in the GitHub Package Registry. In order to access them, a personal access token (PAT) is needed. You can create one using the following steps:
```bash
./configure-github.sh
```
