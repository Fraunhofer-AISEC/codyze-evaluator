#!/usr/bin/env python3
import os
import re

def get_dependencies(folder):
    dependencies = set()

    for project in os.listdir(folder):
        project_path = os.path.join(folder, project)
        req_file = os.path.join(project_path, 'requirements.txt')

        if os.path.isdir(project_path) and os.path.isfile(req_file):
            with open(req_file, 'r') as file:
                for line in file:
                    # Remove version info using regex
                    dependency = re.sub(r'([<>=!~].*)', '', line).strip()
                    if dependency:  # Add only non-empty dependencies
                        dependencies.add(dependency)

    return sorted(dependencies)

components_folder = '../components'
unique_dependencies = get_dependencies(components_folder)

# Output the list of unique dependencies
for dep in unique_dependencies:
    print(dep)