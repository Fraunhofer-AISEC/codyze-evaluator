# Providing negative test results

This repository contains specific versions of selected OpenStack components which we used for testing.
In particular, it contains some violations against the rules we implemented.
To see if the results of the analysis are correct, we would normally expect the OpenStack checker to find these violations.
However, it is also desirable to test the OpenStack checker with a project that does not contain the respective violations.

As the projects are cloned via git submodules, we can make use of git's patch functionality to apply certain changes to the code.
We provide patch files in the directory [extenal/patch-files](https://github.com/Fraunhofer-AISEC/openstack-checker/external/patch-files).
The patch files are named by the project they have to be applied to.
These can be applied to the respective projects using `git apply <patch-file>`.

As an example, you can navigate to the directory for magnum and apply the patch file `magnum.2.patch` as follows:
```bash
cd external/magnum
git apply ../patch-files/magnum.2.patch
```
You can now run the OpenStack checker on this version of magnum.

To revert the changes again, you can run `git stash` inside the respective project's directory.