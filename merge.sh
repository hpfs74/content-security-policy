#!/usr/bin/env bash



set -e

TEMPLATE_DIR='aws-infra-templates'

if [ ! -d $TEMPLATE_DIR ]; then
  echo "Template directory not found, make sure you cloned with submodules"
  exit 2
fi

# Run the templated run script from the template module
cd $TEMPLATE_DIR

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

ls -l
pwd
# Copy over the app-specifics first
cp -R ./context ../
cp -R ./roles ../
cp -R ./terraform ../
cp ./ansible.cfg ./hosts ../
