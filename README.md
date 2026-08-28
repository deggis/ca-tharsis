# ca-tharsis

![ca-tharsis logo](https://github.com/deggis/ca-tharsis/blob/master/img/ca-tharsis.jpg)

*ca-tharsis project logo, ink on premium toilet paper, 2024*

# Summary

ca-tharsis as tool for reviewing Microsoft Entra ID Conditional Access policy sets.

Currently, ca-tharsis helps mostly in understanding the user assignment coverage for the tenant user base. It does this by evaluating the assignments fully for each policy and supporting report creation for it.

ca-tharsis has also other features, like extracting users with admin roles and experimental support for resolving CA coverage using a constraint solver. The most useful feature however, the report of non-overapping *artificial groups* (disjoint-sets) of the user base, was originally just an ingredient for the constraint solver.


# Installation

```
pip install -r requirements.txt
```

# Usage

```
mkdir [DATA_DIR]
az login --tenant [TENANT]
python3 main.py [WORKDIR]
```

See output and HTML reports in the workdir (dir will be created if missing).


# Conditional Access policies

In a Microsoft identity ecosystem, Microsoft Entra ID Conditional Access policies have an important role in defining required security controls for each login. As an oversimplication, they control whether or not Multi-Factor Authentication (MFA) requirement is applied.

All Conditional Access (CA) policies are evaluated for every sign-in, but if the login does not meet targeting of the policies, no additional controls are applied on top of username+password.

Challenges:

 - Because all CA policies are evaluated for each sign-in, this requires exemptions of all categories to be maintained within each policy
 - Inclusions and exemptions can be added individually, through roles or groups or with a combination of these.
 - The net result of user inclusions and exclusions is not visible in the portal for any single policy. Yet, to succeed, the CA policy maintainer should have clear picture on how the policies play together as a whole.

In summary, while these policies are simple to create, they are notoriously difficult to maintain and review. The portal provides a *what-if tool* for spot checking single sign-in scenarios, but does not provide the much needed overall visibility to what is applied, and what the weaknesses are.


# Caveats in editing Conditional Access policies

(And if they are addressed here)

- Firstly, the Conditional Access editor doesn't even show how big portion of the user base each of the policy covers.
	- We get that in the policy summary reporting here
- Conditional Access editor doesn't display what CA policies are similar to each other. Everything must be stated in the policy name.
	- We are able to do visual comparisons in the ca-tharsis summary report

To be verified:
- Selecting all device platforms does not mean policy would apply to all platforms? If you select Windows, Linux, iOS, Android, will a FreeBSD User-Agent will be picked by the policy? It it would, why?
	- We can handle this kind of situations by inserting an artificial UnmentionedPlatform like we handle applications.

# Caveats in ca-tharsis tool

CA policy conditions apart from user and resource targeting have little to no support:
- Device filters with query
- Application query filters
- Location support
- etc

Other:

- User & app targetting: if there is a huge number of policies (100+) with each having  user & app exclusions unique to each policy (like a lot), the number of variables might grow too big for the solver.


# Other work

- caOptics: https://github.com/jsa2/caOptics
- Factorio-SAT Nothing do with Entra but looks cool [https://github.com/R-O-C-K-E-T/Factorio-SAT](https://github.com/R-O-C-K-E-T/Factorio-SAT)
- what-if tool: https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool
- Conditional access workbook: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-conditional-access-gap-analyzer
- Signin logs/panel
