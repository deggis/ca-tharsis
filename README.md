
# ca-tharsis

![ca-tharsis logo](https://github.com/deggis/ca-tharsis/blob/master/img/ca-tharsis.jpg)

*ca-tharsis project logo, ink on premium toilet paper, 2024*

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

This answer is searched by re-expressing the Conditional Access policy set as logical implications, and later requiring the solver to minimize the *cost-to-attack*.

# Method

- Re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets)
	- As an accidental byproduct, we're able to create relatively compact reporting of existing policies
- Re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets). Within these groups, the applied policy requirements are equal. These groups get equal treatment from the policies.
- Same for apps
- Create a model 
	- Each policy is expressed as a logical implication using cpmpy variables, where if combination of parameters evaluates to true, a deny/grant/grant with controls is applied
	- We later use cpmpy to translate this model for a constraint solver
	- Example: (*artificial_group1* | *artificial_group2*) & device_platform => grant but require MFA
- cost-to-attack (objective function):
  - There are default weights in place. Main idea: guessing a single exempted user or application is harder than a situation where half of users or half of target apps are exempted.
  - These don't need to be perfect: Out of hundreds of possible scenarios, we mainly want to find any low-cost scenarios and we are not here to put them in perfect order.
	- Note: These numbers are pulled out of thin air
  - TODO: Make weights configurable.
- Solutions
	- There are always solutions
- Assumption: there aren't tons of exclusion groups that are unique to each policy definition

# Method (again but with images)

# Requirements

See requirements.txt. cpmpy, pandas.

# Installation

```
pip install -r requirements.txt
```

# Usage

```
az cli --tenant [TENANT]
python3 main.py [WORKDIR]
```

See output and HTML reports in the workdir.

# Other work

- what-if
- Caoptics: use this
- Factorio-SAT Nothing do with Entra but looks cool [https://github.com/R-O-C-K-E-T/Factorio-SAT](https://github.com/R-O-C-K-E-T/Factorio-SAT)
- Conditional access workbook
- Signin logs/panel