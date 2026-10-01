#!/bin/sh
set -eu

local_only=false
if [ "${1:-}" = "--local-only" ]; then
    local_only=true
    shift
fi
if [ "$#" -gt 1 ]; then
    printf '%s\n' 'usage: validate.sh [--local-only] [aws-profile]' >&2
    exit 64
fi
profile=${1:-plntir-root-bootstrap}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
template="$root/infra/bootstrap/aws-root-bootstrap.yaml"
state_template="$root/infra/state/aws-terraform-state.yaml"

test -f "$template"
test ! -L "$template"
test -f "$state_template"
test ! -L "$state_template"
python3 - "$template" "$state_template" <<'PY'
import pathlib
import sys
import yaml

path = pathlib.Path(sys.argv[1])
state_path = pathlib.Path(sys.argv[2])
class Loader(yaml.SafeLoader):
    pass
def cloudformation(loader, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)
Loader.add_multi_constructor('!', lambda loader, suffix, node: cloudformation(loader, node))
document = yaml.load(path.read_text(encoding='utf-8'), Loader=Loader)
resources = document.get('Resources', {})
assert 'BuilderUser' in resources
assert 'OwnerUser' in resources
assert 'BootstrapAdminRole' in resources
assert 'BreakGlassRole' in resources
text = path.read_text(encoding='utf-8')
assert 'AWS::IAM::AccessKey' not in text
assert 'LoginProfile:' not in text
assert 'lightsail:OpenInstancePublicPorts' in text
assert 'Effect: Deny' in text
assert 'lightsail:PeerVpc' in text
assert 'ec2:AuthorizeSecurityGroupIngress' in text
assert 'ec2:AuthorizeSecurityGroupEgress' in text
assert 'ServiceRolePermissionsBoundary:' in text
assert 'iam:PermissionsBoundary' in text
assert 'iam:PolicyARN: arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore' in text
assert 'ServiceRolePermissionsBoundaryArn:' in text
assert 'apigateway:POST' in text
assert 'rolesanywhere:CreateTrustAnchor' in text
assert 'rolesanywhere.amazonaws.com' in text
assert 'lambda:PutFunctionConcurrency' in text
assert len(text.encode('utf-8')) < 51_200

state = yaml.load(state_path.read_text(encoding='utf-8'), Loader=Loader)
state_resources = state.get('Resources', {})
assert state_resources['TerraformStateBucket']['Type'] == 'AWS::S3::Bucket'
assert state_resources['TerraformStateKey']['Type'] == 'AWS::KMS::Key'
state_text = state_path.read_text(encoding='utf-8')
assert 'AccessControl: PublicRead' not in state_text
assert 'BlockPublicAcls: true' in state_text
assert 'BucketKeyEnabled: true' in state_text
assert 'VersioningConfiguration:' in state_text
assert len(state_text.encode('utf-8')) < 51_200
print('PASS local bootstrap invariants')
PY

if [ "$local_only" = true ]; then
    exit 0
fi

aws cloudformation validate-template \
    --profile "$profile" \
    --region eu-central-1 \
    --template-body "file://$template" >/dev/null
aws cloudformation validate-template \
    --profile "$profile" \
    --region eu-central-1 \
    --template-body "file://$state_template" >/dev/null
printf '%s\n' 'PASS AWS CloudFormation template validation (identity and state)'
