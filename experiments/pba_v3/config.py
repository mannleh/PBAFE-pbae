"""Central configuration for PBA/3 experiments.

Every experiment module imports its defaults from here. Do not scatter
magic numbers across runners: the manuscript macros are generated from the
same values, so a change here must be followed by a release rebuild.
"""

CONFIG_VERSION = "PBA3/config-v1"

# --- Core protocol / workload grid -----------------------------------------
DIMENSION = 256               # fast grid; every reported headline number must
                              # also be produced at FINAL_DIMENSION (P3.3)
FINAL_DIMENSION = 6241        # matches the UNSW-NB15 MLP parameter count
SEGMENTS = 16                 # default segment count for the middle tier
BUDGET = 3                    # record-level spot budget
CLIENTS = 30
ROUNDS = 60
SEEDS = 100
SEED_START = 0
QUICK_SEEDS = 8               # tuning only; never used in a paper table
ATTACK_ONSET_ROUND = 9        # first attacked round id, matching release_v3

WORKLOADS = ("persistent", "random", "withholding")
SCHEDULES = ("uniform", "round_robin", "adaptive", "sealed_adaptive")
OPPONENTS = ("honest", "reactive", "copycat", "withhold", "withhold_smart")

# --- Release / anchor references ------------------------------------------
ANCHOR = {
    "workload": "withholding",
    "adaptive_inconclusive": 47.260,
    "uniform_inconclusive": 10.460,
    "adaptive_sd": 4.655,
    "uniform_sd": 3.050,
    "tolerance": 0.005,
}

BASELINE_REF = "experiments/pba_v3/results/baseline_ref.json"
RELEASE_DIR = "experiments/pba_v3/results/release_v4"
