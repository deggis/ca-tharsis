
# ca-tharsis

Find weaknesses in Microsoft Entra ID Conditional Access policies using constraint solving.

In a Microsoft ecosystem Conditional Access policies have an important role in identity secury. As an oversimplication, they control whether or not MFA is applied.

While these policies are simple, they are notoriously difficult to maintain and review.

ca-tharsis aims specifically to answer one question: how lucky the adversary needs to be in choosing suitable user and other authentication conditions to be able to bypass controls such as MFA?

# Method

- Re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets)
	- As a byproduct, we're able to create relatively compact reporting of existing policies
- Re-express the policy user targeting using non-overapping *artificial groups* (disjoint-sets). Within these groups, the applied policy requirements are equal. These groups get equal treatment from the policies.
- Same for apps
- Create a model 
	- Each policy is expressed as a logical implication using cpmpy variables, where if combination of parameters evaluates to true, a deny/grant/grant with controls is applied
	- We later use cpmpy to translate this model for a constraint solver
	- Example: (*artificial_group1* | *artificial_group2*) & device_platform => grant but require MFA
- Fitness/cost function: 
	- Note: These numbers are pulled out of thin air
	- The cost function is *cost-to-attack* which we humbly ask the solver to minimize for us
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