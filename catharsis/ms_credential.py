from azure.identity import AzureCliCredential
from azure.identity import ManagedIdentityCredential

from catharsis.typedefs import RunConf


def get_ms_credential(args: RunConf):
    if args.auth == 'azcli':
        return AzureCliCredential()
    elif args.auth == 'systemassignedmanagedidentity':
        return ManagedIdentityCredential()
    else:
        raise Exception('Unknown auth mode: %s' % args.auth)