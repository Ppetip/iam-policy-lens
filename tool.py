"""Review AWS-style identity policy JSON for broad allows and explain statement-level evidence."""
import fnmatch

def values(value):
    return [value] if isinstance(value,str) else value

def analyze(data):
    statements = data['policy'].get('Statement', [])
    if isinstance(statements,dict):
        statements = [statements]
    findings = []
    for index,statement in enumerate(statements):
        if statement.get('Effect') != 'Allow':
            continue
        def add(kind, reason):
            findings.append(dict(kind=kind,statement=index,sid=statement.get('Sid'),reason=reason,conditional=bool(statement.get('Condition'))))
        if 'NotAction' in statement or 'NotResource' in statement:
            add('allow_complement', 'Allow with NotAction/NotResource needs manual review.')
        actions = values(statement.get('Action', []))
        resources = values(statement.get('Resource', []))
        if any('*' in a or '?' in a for a in actions):
            add('wildcard_action', 'Wildcard actions can include future API operations.')
        if '*' in resources:
            add('all_resources', 'Resource wildcard grants scope across resources where supported.')
        if any(fnmatch.fnmatchcase('iam:PassRole'.lower(),a.lower()) for a in actions) and '*' in resources:
            add('passrole_scope', 'Constrain PassRole to specific roles and services.')
        principal = statement.get('Principal')
        if principal == '*' or isinstance(principal,dict) and '*' in values(principal.get('AWS',[])):
            add('public_principal', 'Public principal requires resource-policy context.')
    return findings


def main():
    import argparse, json, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='path to JSON input, or - for stdin')
    args = parser.parse_args()
    try:
        if args.input == '-':
            data = json.load(sys.stdin)
        else:
            with open(args.input, encoding='utf-8') as stream:
                data = json.load(stream)
        result = analyze(data)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        print('Invalid input: '+str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
