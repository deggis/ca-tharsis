
# ca-tharsis

![ca-tharsis logo](https://github.com/deggis/ca-tharsis/blob/master/img/ca-tharsis.jpg)

*ca-tharsis project logo, ink on premium toilet paper, 2024*

This is an art project. Needing to use python-scraping-with-analysis to review configuration of a  cloud identity platform is like needing to send a retired cop with technology anxiety to stop a cyber-attack.

Project status: unstable PoC

# Conditional Access policies

In a Microsoft identity ecosystem, Microsoft Entra ID Conditional Access policies have an important role in defining required security controls for each login. As an oversimplication, they control whether or not Multi-Factor Authentication (MFA) requirement is applied.

All Conditional Access (CA) policies are evaluated for every sign-in, but if the login does not meet targeting of the policies, no additional controls are applied on top of username+password.

Challenges:

 - Because all CA policies are evaluated for each sign-in, this requires exemptions of all categories to be maintained within each policy
 - Inclusions and exemptions can be added individually, through roles or groups or with a combination of these.
 - The net result of user inclusions and exclusions is not visible in the portal for any single policy. Yet, to succeed, the CA policy maintainer should have clear picture on how the policies play together as a whole.

In summary, while these policies are simple to create, they are notoriously difficult to maintain and review. The portal provides a *what-if tool* for spot checking single sign-in scenarios, but does not provide the much needed overall visibility to what is applied, and what the weaknesses are.

# ca-tharsis summary

ca-tharsis finds weaknesses in Conditional Access policies using a constraint solver.

ca-tharsis aims specifically to answer one question: how lucky the adversary needs to be in order to bypass MFA and other controls? In other words, what sign-in scenarios offer the least resistance to an adversary.

This answer is searched by re-expressing the Conditional Access policy set as logical implications, and later requiring the solver to minimize the *cost-to-attack*. ca-tharsis uses Google Optimization Tools (`OR-Tools`) through `cpmpy` library.

# Method

Note: Conditional Access policy editor uses terms like "assignment", "conditions", "target resources". These refer to the same thing: if a sign-in event matches what's configured in the policy, it will be applied. If not, the policy is not effective and does not contribute any additional controls to that sign-in event.

CA policy set is a list of if-then rules. ca-tharsis needs to massage the definitions a bit before we can express the conditions as `cpmpy` if-then rules (logical implications).

## Step 1: Gather referenced data for policies

- Policies can include and exclude target users directly or using groups or roles.
- We first evaluate all members of all referenced groups or roles
- We then re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets)
- We repeat the same for application targeting.

Now, within these artificial user groups, **AUG's**, and application groups **AAG's**, all policies behave similarly. Pick any user from the same group and the `what-if` tool should give same results.

## Step 2: Reduce policies to lists of booleans

We dig the information for the rest of the referenced policy filters and re-create an internal representation for them: a list of booleans, yes/no flags, that are shared between all policies.

As an accidental byproduct of this (especially the Step 1), we're able to create relatively compact reporting of existing policies using artificial user/application groups, for example:

- How many and which users are targeted
- How many and which applications are targeted
- What controls are included

## Step 3: Translate the lists of booleans as cpmpy logical model

Create a `cpmpy` model that consists of three parts:

1. The policy
	- Each policy is expressed as a logical implication using cpmpy boolean variables, where if combination of parameters evaluates to true, a deny/grant/grant with controls is applied
	- Example: `(AUG1 | AUG2) & Android => MFA` 
	- Example: `AUG3 & (AAG1 | AAG2 | AAG3) => BLOCK`
2. Additional task requirements
	- These are needed as our model doesn't otherwise know what is possible for a sign-in scenario
	- For a solution, we require that only a single user group is selected
	- `AUG1 ^ AUG2 ^ AUG3 ..`
	- Same with application groups, user-risks and sign-in risks.
3. cost-to-attack weights
	- The goal is to find scenarios that present the cheapest cost-to-attack scenarios
	- We create a numerical cost vector holding the cost for each boolean for being true
	- This is the task we give to cpmpy: find solutions that minimize the cost vector.

Additionally, we try to minimize the number of introduced variables to have easier time later in summarizing the report and to help the solver.

Main ideas about the cost vector:

- There are default weights in place.
- A policy gap with no controls for 1 user is not as bad as a gap for 50 % of the user base.
- In reality, perfect ordering is highly environment dependant.
- This doesn't need to be perfect to be useful: Out of hundreds of possible scenarios, we mainly want to find any low-cost scenarios and we are not here to put them in perfect order.

# Requirements

See requirements.txt. cpmpy, pandas.

# Installation

```
pip install -r requirements.txt
```

# Usage

```
az login --tenant [TENANT]
python3 main.py [WORKDIR]
```

See output and HTML reports in the workdir (dir will be created if missing).

The tool will run following queries using az cli unless the result file exists already in the `WORKDIR`:

 * `az rest --uri https://graph.microsoft.com/beta/identity/conditionalAccess/policies`
 * `az rest --uri https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers`
 * `az rest --uri https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId+eq+'{role_id}'`
 * `az rest --uri https://graph.microsoft.com/v1.0/users`

# Interpreting the results

There will always be as many solutions as requested.

Ideally, all the findings are intended omissions.


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

In current state, likely buggy.

Partial implementation (only checks if these are included or not)

- Session controls

Not implemented

- Device filters with query
- Application query filters
- Location support
- Guest memberships

Other:

- User & app targetting: if there is a huge number of policies (100+) with each having  user & app exclusions unique to each policy (like a lot), the number of variables might grow too big for the solver. But if this is the case, the maintainability is already in trouble.

# Method (again but with images)

TODO: Add rest.

## Step 3: Model

```
# Policy
(and([or([UG1, UG2, UG3, UG4]), (AG0) or (AG1), (ClientAppType:exchangeActiveSync) or (ClientAppType:other)])) -> (Control:block),
(and([or([UG2, UG3, UG4]), (AG0) or (AG1), (SigninRisk:medium) or (SigninRisk:high)])) -> (Control:mfa),
((or([UG2, UG3, UG4])) and ((AG0) or (AG1))) -> (Control:mfa),
boolval(True),  # seems like a CA policy which is enabled but does not contain anything

# Additional task requirements
UG1 xor UG2 xor UG3 xor UG4 xor UG0,
AG0 xor AG1,
ClientAppType:browser xor ClientAppType:mobileAppsAndDesktopClients xor ClientAppType:exchangeActiveSync xor ClientAppType:other,
SigninRisk:none xor SigninRisk:medium xor SigninRisk:high,

# Cost-to-attack weights, referring the cost vector indices
(UG0) -> (IV0 == 1),
(UG1) -> (IV0 == 2),
(UG2) -> (IV0 == 17),
(UG3) -> (IV0 == 1),
(UG4) -> (IV0 == 1),
(AG0) -> (IV1 == 2),
(AG1) -> (IV1 == 1),
(Control:block) -> (IV5 == 1000),
(~Control:block) -> (IV5 == 0),
(Control:mfa) -> (IV6 == 500),
(~Control:mfa) -> (IV6 == 0),
(SigninRisk:none) -> (IV3 == 30),
(SigninRisk:medium) -> (IV3 == 5),
(SigninRisk:high) -> (IV3 == 0),
IV4 == 0, # Zero currently unused variables
IV2 == 0
```

# Other work

- caOptics: https://github.com/jsa2/caOptics
- Factorio-SAT Nothing do with Entra but looks cool [https://github.com/R-O-C-K-E-T/Factorio-SAT](https://github.com/R-O-C-K-E-T/Factorio-SAT)
- what-if tool: https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool
- Conditional access workbook: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-conditional-access-gap-analyzer
- Signin logs/panel


# Security considerations

- Path injection: Azure resource id's (GUIDs, some names) are used as part of local file names. Azure does not allow special characters in these fields.
  - TODO: still, sanitize these anyway