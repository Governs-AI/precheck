import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "policy.schema.json"
EXAMPLES_DIR = ROOT / "examples" / "policies"
EXPECTED_EXAMPLES = ["enterprise.yaml", "minimal.yaml", "standard.yaml"]


def _load_schema():
    return json.loads(SCHEMA_PATH.read_text())


def _load_policy(path: Path):
    return yaml.safe_load(path.read_text())


def _policy_examples():
    return sorted(EXAMPLES_DIR.glob("*.yaml"))


def test_expected_example_policies_exist():
    assert [path.name for path in _policy_examples()] == EXPECTED_EXAMPLES


def test_policy_schema_is_valid_json_schema():
    Draft202012Validator.check_schema(_load_schema())


@pytest.mark.parametrize("policy_path", _policy_examples(), ids=lambda path: path.stem)
def test_example_policy_validates_against_schema(policy_path: Path):
    validator = Draft202012Validator(_load_schema())
    policy = _load_policy(policy_path)

    errors = sorted(
        validator.iter_errors(policy),
        key=lambda error: list(error.absolute_path),
    )

    assert not errors, "\n".join(
        f"{policy_path.name}: {'/'.join(map(str, error.absolute_path))} {error.message}"
        for error in errors
    )
