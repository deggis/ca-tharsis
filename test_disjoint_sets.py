import unittest
from disjoint_sets import *

class TestStringMethods(unittest.TestCase):

    def test_empty_works(self):
        task_groups, artificial_groups = split_to_disjoint_sets([])
        self.assertEqual(task_groups, {})
        self.assertEqual(artificial_groups, {})

    def test_small_grouping(self):
        """
        Names are "policy" and "user". These are just examples.
        Any identifiers can be used to group anything, the object
        type does not matter.
          
          pol/user user1  user2  user3  user4  user5  user6  user7  user8  user9  user10 user11 user12 user13 user14 user15 user16 user17 user18 user19 user20
          policy1  x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x     
          policy2  x      x      x      x      x      x      
          policy3  x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x
          policy4                       x                                         x      x
          policy5                                     x
          
          "AUG"    0      0      0      1      0      2      3      3      3      5      5      3      3      3      3      3      4      4      4      4
        
        The order of Artificial User Groups is deterministic but meaningless.
        """
        
        pol1_users = set(range(1,21))  # 1-20
        pol2_users = set(range(1,7))   # 1-6
        pol3_users = set(range(1,17))  # 1-16
        pol4_users = set([4,10,11])
        pol5_users = set([6])

        groups = [
            GroupMembers('pol1', pol1_users),
            GroupMembers('pol2', pol2_users),
            GroupMembers('pol3', pol3_users),
            GroupMembers('pol4', pol4_users),
            GroupMembers('pol5', pol5_users)
        ]

        task_groups, artificial_groups = split_to_disjoint_sets(groups)
        tg, ag = task_groups, artificial_groups

        # Check which users belong to which group
        self.assertEqual(ag[0], {1,2,3,5})
        self.assertEqual(ag[1], {4})
        self.assertEqual(ag[2], {6})
        self.assertEqual(ag[3], {7,8,9,12,13,14,15,16})
        self.assertEqual(ag[4], {17,18,19,20})
        self.assertEqual(ag[5], {10,11})

        # Check which groups are referenced from each policy
        self.assertEqual(tg['pol1'], [0,1,2,3,4,5])
        self.assertEqual(tg['pol2'], [0,1,2])
        self.assertEqual(tg['pol3'], [0,1,2,3,5])
        self.assertEqual(tg['pol4'], [1,5])
        self.assertEqual(tg['pol5'], [2])

    def test_small_grouping_ordered(self):
        """
        Names are "policy" and "user". These are just examples.
        Any identifiers can be used to group anything, the object
        type does not matter.
          
          pol/user user1  user2  user3  user4  user5  user6  user7  user8  user9  user10 user11 user12 user13 user14 user15 user16 user17 user18 user19 user20
          policy1  x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x     
          policy2  x      x      x      x      x      x      
          policy3  x      x      x      x      x      x      x      x      x      x      x      x      x      x      x      x
          policy4                       x                                         x      x
          policy5                                     x
          
          "AUG"    1      1      1      4      1      5      0      0      0      3      3      0      0      0      0      0      2      2      2      2
        
        Same as above, but
        Artificial User Groups are ordered by their members size in descending order, secondarily by their member ids.
        """
        
        pol1_users = set(range(1,21))  # 1-20
        pol2_users = set(range(1,7))   # 1-6
        pol3_users = set(range(1,17))  # 1-16
        pol4_users = set([4,10,11])
        pol5_users = set([6])

        groups = [
            GroupMembers('pol1', pol1_users),
            GroupMembers('pol2', pol2_users),
            GroupMembers('pol3', pol3_users),
            GroupMembers('pol4', pol4_users),
            GroupMembers('pol5', pol5_users)
        ]

        task_groups, artificial_groups = split_to_disjoint_sets_ordered(groups)
        tg, ag = task_groups, artificial_groups

        # Check which users belong to which group
        # 0<3, {7,8,9,12,13,14,15,16}
        # 1<4, {1,2,3,5}
        # 2<0, {17,18,19,20}
        # 3<5, {10,11}
        # 4<1, {4}
        # 5<2, {6}

        self.assertEqual(ag[0], {7,8,9,12,13,14,15,16})
        self.assertEqual(ag[1], {1,2,3,5})
        self.assertEqual(ag[2], {17,18,19,20})
        self.assertEqual(ag[3], {10,11})
        self.assertEqual(ag[4], {4})
        self.assertEqual(ag[5], {6})

        # Check which groups are referenced from each policy
        self.assertEqual(tg['pol1'], [0,1,2,3,4,5])
        self.assertEqual(tg['pol2'], [1,4,5])
        self.assertEqual(tg['pol3'], [0,1,3,4,5])
        self.assertEqual(tg['pol4'], [3,4])
        self.assertEqual(tg['pol5'], [5])
