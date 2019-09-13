#!/usr/bin/env sh

set -o errexit
set -o nounset


pyclean () {
  # Cleaning cache:
  find . | grep -E '(__pycache__|\.py[cod]$)' | xargs rm -rf
}

run_ci () {
  echo ">> Starting CI tests! <<"

  export PYTHONPATH=$PWD  # necessary for pytest presetup plugin launch
  export PYTHONDONTWRITEBYTECODE=true  # else troubles with virtualbox shares...


  set +o errexit  # THESE LINTS MUST NOT STOP CHECKS

      # Running linting for all python files in the project:
      # "flake8 ." is too verbose for now, and would need to be made compatible with Black
      echo "Running pylint"
      pylint **/*.py

      # Running tests and type checking:
      echo "Running mypy"
      mypy src  # Some mixin errors are impossible to workaround now...

  set -o errexit

  echo "Running pytest"
  pytest --disable-warnings
  pytest --dead-fixtures --dup-fixtures

  # Running code-quality check:
  echo "Running xenon"
  xenon --max-absolute B --max-modules B --max-average A server

  # Checking if all the dependencies are secure and do not have any
  # known vulnerabilities:
  echo "Running safety check"
  safety check --bare --full-report

  # Checking `pyproject.toml` file contents and dependencies status:
  echo "Running poetry & pip checks"
  poetry check && pip check

  # Checking docs:
  echo "Running doc8"
  doc8 --max-line-length 3000 -q docs

  # Checking `yaml` files:
  #echo "Running yamllint"
  yamllint -d '{"extends": "default", "ignore": "build"}' -s .

  # Checking `.env` files:
  #echo "Running dotenv-linter"
  #dotenv-linter .env

  # Checking translation files, ignoring ordering and locations:
  #echo "Running polint"
  #polint -i location,unsorted locale

  # Also checking translation files for syntax errors:
  #if find locale -name '*.po' -print0 | grep -q "."; then
  #  # Only executes when there is at least one `.po` file:
  #  echo "Running dennis-cmd lint"
  #  dennis-cmd lint --errorsonly locale
  #fi

  echo ">> All CI tests were executed! <<"
}

# Remove any cache before the script:
pyclean

# Hook to clean everything up on ctrl-C:
trap pyclean EXIT INT TERM

# Run the CI process:
run_ci
