
# ca-tharsis

![ca-tharsis logo](https://github.com/deggis/ca-tharsis/blob/master/img/ca-tharsis.jpg)

*ca-tharsis project logo, ink on premium toilet paper, 2024*

This is an art project. Needing to use python-scraping-with-analysis to verify configuration of a premium cloud security platform is like sending a retired cop with anxiety towards technology to stop a cyber-attack.

# Conditional Access policies

In a Microsoft identity ecosystem, Microsoft Entra ID Conditional Access policies have an important role in defining required security controls for each login. As an oversimplication, they control whether or not MFA is applied.

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

It's an if-then engine. ca-tharsis needs to massage the definition a bit before we can express the conditions as if-then rules (logical implications) with cpmpy.

## Step 1: Minimize the need for variables

- Policies can include and exclude target users directly or using groups or roles.
- We first evaluate all members of all referenced groups or roles
- We then re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets)
- We repeat the same for application targeting.

Now, within these artificial user groups, **AUG's**, and application groups **AAG's**, all policies behave similarly. Pick any user from the same group and the `what-if` tool should give same results.

## Step 2: Internal representation of policy objects

We dig the information for the rest of the referenced policy filters and re-create them.

As an accidental byproduct of this (especially the Step 1), we're able to create relatively compact reporting of existing policies using artificial user/application groups:

- How many users are targeted
- What applications are targeted
- What controls are included

## Step 3: Re-create the policy as logical model

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
	- First we simply require that the sign-in is not resulting to block with `~block`.
	- We got this far with boolean variables.
	- For everything else, we create a numerical cost vector
	- For all boolean variables, we assign a cost for being true
	- This is the task we give to cpmpy: find solutions that 1) don't result in BLOCK, 2) minimize the cost vector.

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

Ideally, 


# Caveats in editing Conditional Access policies

(And if they are addressed here)

- Firstly, the Conditional Access editor doesn't even show how big portion of the user base each of the policy covers.
	- We get that in the policy summary reporting here
- Conditional Access editor doesn't display what CA policies are similar to each other. Everything must be stated in the policy name.
	- We are able to do visual comparisons in the ca-tharsis summary report

# Caveats in ca-tharsis tool

Partial implementation (only checks if these are included or not)

- Session controls

Not implemented

- Device filters with query
- Application query filters
- Location support

Other:

- User & app targetting: if there is a huge number of policies (100+) with each having  user & app exclusions unique to each policy (like a lot), the number of variables might grow too big for the solver. But if this is the case, the maintainability is already in trouble.

# Method (again but with images)

TODO


# Other work

- what-if
- Caoptics: use this
- Factorio-SAT Nothing do with Entra but looks cool [https://github.com/R-O-C-K-E-T/Factorio-SAT](https://github.com/R-O-C-K-E-T/Factorio-SAT)
- Conditional access workbook
- Signin logs/panel