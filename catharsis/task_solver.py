from catharsis.ca import create_policymodels
from catharsis.solver import translate_policymodels_to_task
from catharsis.typedefs import RunConf
from catharsis.graph_query import get_all_users
from catharsis import utils

import logging
logger = logging.getLogger('catharsis.task_solver')
logger.setLevel(logging.INFO)


solver_imports_available = True
try:
  import cpmpy as cp
  from cpmpy.solvers.ortools import OrtSolutionPrinter
except ImportError:
  cp = None
  OrtSolutionPrinter = None
  solver_imports_available = False

async def do_task_solver(args: RunConf):
  if not solver_imports_available:
    raise Exception("cpmpy related libraries are not available!")
  logger.warning('This solver is really, really experimental.')

  all_users = list((await get_all_users(args)).values())
  active = [u for u in all_users if utils.is_principal_account_enabled(u)]
  policy_models, generalInfo = await create_policymodels(args, active)

  # create model
  translate_policymodels_to_task(args, policy_models, generalInfo)
  logger.info('Task ready.')


def add_solver_subparser(subparsers):
  solver_parser = subparsers.add_parser('solver')
  solver_parser.set_defaults(task_func=do_task_solver)
  solver_parser.add_argument('--number-of-solutions', type=int, default=5)