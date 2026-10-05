# Architecture & Technical Reference: Risk-Adaptive Proof-of-Work Middleware

> **Document Purpose**: Complete technical reference manual for the Risk-Adaptive PoW Middleware research testbed. This document enables an engineer or researcher to understand, trace, debug, modify, and defend every component, algorithm, mathematical derivation, experimental ablation, and security boundary in the system.

---

# Table of Contents
1. [System Architecture & Data Flow](#1-system-architecture--data-flow)
2. [Hot-Path Gateway Deep Dive (`src/middleware/`)](#2-hot-path-gateway-deep-dive-srcmiddleware)
3. [Out-of-Band Scoring Pipeline (`src/worker/`)](#3-out-of-band-scoring-pipeline-srcworker)
4. [Mathematical Derivations & Core Algorithms](#4-mathematical-derivations--core-algorithms)
5. [Client SDK & Solver Hardware Profiles (`src/client/`)](#5-client-sdk--solver-hardware-profiles-srcclient)
6. [Adversary Engines & Threat Models (`src/traffic/`)](#6-adversary-engines--threat-models-srctraffic)
7. [Metrics & Evaluation Methodology (`src/evaluation/`)](#7-metrics--evaluation-methodology-srcevaluation)
8. [Experimental Catalog (Phases 1–8)](#8-experimental-catalog-phases-18)
9. [Security Assumptions & Fundamental Boundaries](#9-security-assumptions--fundamental-boundaries)
10. [Developer & Debugging Playbook ("Let's Modify the Controller")](#10-developer--debugging-playbook)
11. [Reproducibility & Verification](#11-reproducibility--verification)

---

# 1. System Architecture & Data Flow

The middleware operates as an inline reverse proxy with decoupled, asynchronous out-of-band behavioral scoring to keep the hot path latency overhead below $0.12\text{ ms}$.

```
                             [ INCOMING HTTP REQUEST ]
                                         │
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │        FastAPI Reverse Proxy Gateway          │
                 │              (src/middleware/)                │
                 └───────────────────────┬───────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
            [ Authorization: Bearer <work_credit_token> ]       [ Missing / Invalid Header ]
                   │                                           │
                   ▼                                           ▼
      ┌─────────────────────────┐                 ┌─────────────────────────┐
      │ Work Credit Fast-Path   │                 │ PoW Solution Header     │
      │  - HMAC signature check │                 │  X-PoW-Solution present?│
      │  - Expiry TTL check     │                 └────────────┬────────────┘
      │  - (client, endpoint)   │                              │
      │    binding match        │                ┌─────────────┴─────────────┐
      └────────────┬────────────┘               [ No ]                      [ Yes ]
                   │                             │                           │
          ┌────────┴────────┐                    ▼                           ▼
       [ Valid ]       [ Invalid ]     ┌──────────────────┐        ┌──────────────────┐
          │                 │          │ Return HTTP 401  │        │ Verify PoW &     │
          ▼                 ▼          │ Challenge Token  │        │ Replay Nonce     │
     (Fast-Path)       (Fall Through   │ (d read from     │        └─────────┬────────┘
     ┌───────────┐     to PoW Check)   │  Redis cache)    │                  │
     │ Upstream  │                     └──────────────────┘          ┌───────┴───────┐
     │ Target    │                                              [ Pass ]         [ Fail ]
     │ App       │                                                 │                │
     └───────────┘                                                 ▼                ▼
          ▲                                                ┌──────────────┐   ┌──────────────┐
          │                                                │ Issue Work   │   │ HTTP 403 /   │
          └────────────────────────────────────────────────┤ Credit Token │   │ 401 Re-issue │
                                                           │ & Proxy Req  │   └──────────────┘
                                                           └──────────────┘
                                         │
                         (Non-blocking Telemetry Emission)
                                         │
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │       Redis Telemetry Event Stream (XADD)     │
                 └───────────────────────┬───────────────────────┘
                                         │
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │     Async Scoring Worker (src/worker/)        │
                 │  1. FeatureBuilder: 7-D Sliding Window Matrix │
                 │  2. IsolationForest: Unsupervised Anomaly $s$ │
                 │  3. RiskCalibrator: Isotonic Regression $p$   │
                 │  4. DampedController: Closed-Loop $d^*(p)$    │
                 │  5. SET risk:client_key $d \to$ Redis (~0.2ms)│
                 └───────────────────────────────────────────────┘
```

---

# 2. Hot-Path Gateway Deep Dive (`src/middleware/`)

### 2.1 File Map & Responsibilities
- [`src/middleware/server.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/server.py): Reverse proxy entry point using `FastAPI` and `httpx.AsyncClient`. Intercepts all traffic destined for upstream services.
- [`src/middleware/challenge.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/challenge.py): Stateless HMAC challenge minter/verifier, replay protection cache, and work-credit session token manager.
- [`src/middleware/pow_verifier.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/pow_verifier.py): Bit-level leading zero verification engine for SHA-256 and Argon2id.
- [`src/middleware/telemetry.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/telemetry.py): Non-blocking stream publisher pushing raw request telemetry (`XADD`) to Redis.
- [`src/middleware/config.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/config.py): Configuration dataclass (HMAC keys, challenge TTL, Redis URI, target upstream URL).

### 2.2 Challenge Token Serialization
To prevent delimiter injection vulnerabilities with IPv6 addresses (`2001:db8::1`) or composite TLS JA4 fingerprints:
- **Payload Structure**:
  $$\text{Payload} = \{\text{"client\_key"}: k, \text{"endpoint\_class"}: c, \text{"difficulty"}: d, \text{"algorithm"}: a, \text{"issued\_at"}: t, \text{"nonce"}: r\}$$
- **Serialization Format**:
  $$\text{Challenge} = \text{base64url}(\text{json}(\text{Payload})) \,||\, "." \,||\, \text{HMAC-SHA256}_{K_{\text{secret}}}(\text{base64url}(\text{json}(\text{Payload})))$$
- **Security Invariant**: Any modification to `difficulty`, `endpoint_class`, or `client_key` invalidates the HMAC signature in constant time (`hmac.compare_digest`).

### 2.3 Work Credit Session Amortization
- When a client solves a challenge of difficulty $d \ge 8$, the gateway issues a signed work credit token:
  $$\text{Credit} = \text{base64url}(\{\text{"client\_key"}: k, \text{"endpoint\_class"}: c, \text{"expires\_at"}: t + 300\}) \,||\, "." \,||\, \text{HMAC}$$
- **Amortization Rule**: A valid credit bypasses challenge generation for $300\text{ s}$ on that specific endpoint class, keeping legitimate user tax at $p50 = 0.078\text{ ms}$.

### 2.4 Replay Protection Cache
- Located in `ChallengeManager._replay_cache`.
- Stores `(challenge_nonce, solution_nonce) -> expiry_timestamp`.
- Replay verification is $O(1)$ with deterministic timestamp-based expiration sweeps, preventing dual-spend of a solved PoW nonce across parallel requests.

---

# 3. Out-of-Band Scoring Pipeline (`src/worker/`)

### 3.1 File Map & Responsibilities
- [`src/worker/stream_consumer.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/stream_consumer.py): Pulls event batches from Redis Streams via `XREADGROUP`.
- [`src/worker/feature_builder.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/feature_builder.py): Computes 7-dimensional sliding window behavioral matrices per client identity.
- [`src/worker/detector.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/detector.py): Wraps scikit-learn `IsolationForest`, producing inverted raw anomaly decision scores $s \in (-\infty, +\infty)$.
- [`src/worker/calibrator.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/calibrator.py): `RiskCalibrator` mapping raw anomaly scores $s$ to calibrated probabilities of malice $p \in [0, 1]$ via Isotonic Regression.
- [`src/worker/controller.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/controller.py): Implements derived economic difficulty mapping $d^*(p)$, `NaiveController`, and `DampedController`.

### 3.2 7-Dimensional Behavioral Feature Matrix
For each client identity $k$ over a sliding window $W = [t - 30\text{s}, t]$:
1. **$x_1$ (Request Rate)**: $\frac{N}{\Delta t}$ (requests per second).
2. **$x_2$ (Inter-Arrival Mean $\mu_{\text{IA}}$)**: Mean time interval between consecutive requests: $\mu_{\text{IA}} = \frac{1}{N-1} \sum_{i=1}^{N-1} (t_{i+1} - t_i)$.
3. **$x_3$ (Inter-Arrival Variance $\sigma^2_{\text{IA}}$)**: Variance of inter-arrival gaps: $\sigma^2_{\text{IA}} = \frac{1}{N-1} \sum (t_{i+1} - t_i - \mu_{\text{IA}})^2$.
4. **$x_4$ (Burstiness Index)**: Normalized dispersion ratio: $B = \frac{\sigma^2_{\text{IA}}}{\mu^2_{\text{IA}}}$. (Machine cadence $\approx 0$; human web browsing $> 1.5$).
5. **$x_5$ (Endpoint Shannon Entropy)**: $H(E) = -\sum_{e \in \text{Endpoints}} P(e) \log_2 P(e)$. (Targeted attack on `/login` $\approx 0.1$; broad browsing $\approx 1.8$).
6. **$x_6$ (Error Rate)**: Fraction of responses with $4xx / 5xx$ status: $\frac{N_{\text{error}}}{N}$.
7. **$x_7$ (Header Key Shannon Entropy)**: Shannon entropy of request header names and ordering: $H(\text{Headers}) = -\sum P(h) \log_2 P(h)$.

---

# 4. Mathematical Derivations & Core Algorithms

### 4.1 Bit-Level Proof-of-Work Verification Algorithm
Given challenge string $C$, candidate solution nonce $S$, and target difficulty $d$ (bits):
1. Compute digest: $H = \text{SHA256}(C \,||\, S)$ (32 bytes).
2. Count leading zero bits in $H$:
   $$\text{full\_zero\_bytes} = \lfloor d / 8 \rfloor, \quad \text{rem\_bits} = d \pmod 8$$
3. Verify that the first $\text{full\_zero\_bytes}$ of $H$ are $0x00$.
4. Verify that the subsequent byte $H[\text{full\_zero\_bytes}] < (1 \ll (8 - \text{rem\_bits}))$.

```python
# Exact Verification Implementation (src/middleware/pow_verifier.py)
def verify_sha256(challenge_str: str, solution_nonce: str, difficulty_bits: int) -> bool:
    hasher = hashlib.sha256()
    hasher.update(challenge_str.encode("utf-8"))
    hasher.update(solution_nonce.encode("utf-8"))
    digest = hasher.digest()
    
    full_zero_bytes = difficulty_bits // 8
    rem_bits = difficulty_bits % 8
    
    for i in range(full_zero_bytes):
        if digest[i] != 0:
            return False
    if rem_bits > 0:
        mask = 0xFF << (8 - rem_bits) & 0xFF
        if (digest[full_zero_bytes] & mask) != 0:
            return False
    return True
```

### 4.2 Economic Loss Difficulty Derivation ($d^*(p)$) & Bang-Bang Structural Proof
Let:
- $p \in [0, 1]$: Calibrated probability that the request is malicious.
- $B$: Economic benefit extracted by the adversary per admitted request ($B \in [1, 10, 100]$).
- $\lambda$: Weight converting legitimate user latency tax into loss ($\lambda \in [50, 500, 5000]$).
- $t_{\text{base}}$: Baseline HTTP request processing time ($0.01\text{ s} = 10\text{ ms}$).
- $t_{\text{hash, atk}}$: Hash time on adversary hardware ($0.8\,\mu\text{s} = 8 \times 10^{-7}\text{ s}$).
- $t_{\text{hash, ben}}$: Hash time on legitimate client ($4.0\,\mu\text{s} = 4 \times 10^{-6}\text{ s}$).

The adversary solve throughput rate at difficulty $d$ is:
$$\text{rate}(d) = \frac{1}{t_{\text{base}} + 2^d \cdot t_{\text{hash, atk}}}$$

The expected benign latency penalty at difficulty $d$ is:
$$\tau_{\text{benign}}(d) = 2^d \cdot t_{\text{hash, ben}}$$

The system derives the optimal difficulty $d^*(p)$ by minimizing total expected loss:
$$d^*(p) = \arg\min_{d \in [d_{\min}, d_{\max}]} \left[ p \cdot B \cdot \left(\frac{1}{t_{\text{base}} + 2^d \cdot t_{\text{hash, atk}}}\right) + (1-p) \cdot \lambda \cdot \left(2^d \cdot t_{\text{hash, ben}}\right) \right]$$

#### Bang-Bang Structural Behavior & Sensitivity:
Differentiating the loss function reveals why $d^*(p)$ behaves as a sharp step function rather than a smooth continuum:
- For $d \le 10$, $2^d \cdot t_{\text{hash, atk}} \le 1024 \times 0.0008\text{ ms} = 0.819\text{ ms} \ll t_{\text{base}} = 10\text{ ms}$.
- Consequently, $\frac{\partial \text{rate}(d)}{\partial d} \approx 0$ for $d \le 10$: low difficulty levels fail to measurably slow the attacker.
- Meanwhile, the benign user penalty $(1-p) \lambda 2^d t_{\text{hash, ben}}$ grows strictly exponentially in $d$.
- Therefore, for moderate to high $B/\lambda$ ratios ($B/\lambda \ge 0.02$), the optimizer never selects intermediate levels $d \in [3..10]$, jumping discontinuously from $d=2$ directly to $d \ge 12..16$ (**bang-bang transition**).
- *Systems Implication*: This structural bimodality intrinsically accelerates closed-loop limit-cycle chattering, proving why proportional controllers fail and making non-linear controller damping (EWMA, dwell time, slew limiting) mandatory.

### 4.3 Closed-Loop Control Algorithms

#### 4.3.1 Naive Controller (Oscillatory Under Lag $\Delta t$)
$$d_t = d^*(p_t)$$
- Direct memoryless mapping.
- When scoring is delayed by lag $\Delta t$, the gateway evaluates traffic on stale state:
  $$\text{Burst Arrival} \xrightarrow{\Delta t} \text{Difficulty Spikes to } d=16 \xrightarrow{} \text{Client Throttled} \xrightarrow{\Delta t} \text{Difficulty Collapses to } d=2 \xrightarrow{} \text{Burst Resumes}$$
- Produces **147 limit-cycle reversals** per 60s window.

#### 4.3.2 Stabilized Damped Controller
To guarantee asymptotic stability across feedback lags $\Delta t \le 3.0\text{ s}$:
1. **Low-Pass Exponential Moving Average (EWMA)** on raw risk $p_t$:
   $$\bar{p}_t = \alpha \cdot p_t + (1 - \alpha) \cdot \bar{p}_{t-1}, \quad \text{where } \alpha = 0.15$$
2. **Asymmetric Hysteresis**:
   Difficulty escalates only if $p_t - \bar{p}_t \ge \Delta_{\text{up}} = 0.10$; difficulty de-escalates only if $\bar{p}_t - p_t \ge \Delta_{\text{down}} = 0.15$.
3. **Dwell Time Bounding**:
   Enforces a minimum cooldown window $t_{\text{dwell}} = 3.0\text{ s}$ between successive difficulty transitions:
   $$t - t_{\text{last\_change}} \ge 3.0\text{ s}$$
4. **Slew-Rate Limiting**:
   Bounds the maximum step change per control interval to $\pm 1\text{ bit}$:
   $$d_{t} = \text{clip}\left(d^*_t, \, d_{t-1} - 1, \, d_{t-1} + 1\right)$$

---

# 5. Client SDK & Solver Hardware Profiles (`src/client/`)

### 5.1 File Map & Responsibilities
- [`src/client/solver.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/client/solver.py): Multi-threaded PoW solver implementing bit-level search with device-class compute throttling.
- [`src/client/client.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/client/client.py): `PoWClient` HTTP client with automatic 401 interception, challenge extraction, background solving, and work-credit session caching.

### 5.2 Device-Class Compute Profiles
To evaluate equity taxes across heterogeneous client populations:

| Device Profile | Relative Compute Factor | SHA-256 Hash Speed ($t_{\text{hash}}$) | Expected Solve Time at $d=8$ | Expected Solve Time at $d=16$ |
| :--- | :--- | :--- | :--- | :--- |
| **Fast Attacker (Server CPU / GPU)** | $1.00\times$ (Unthrottled) | $0.8\,\mu\text{s} = 0.0008\text{ ms}$ | $0.20\text{ ms}$ | $52.4\text{ ms}$ |
| **Laptop Client** | $1.00\times$ | $1.5\,\mu\text{s} = 0.0015\text{ ms}$ | $0.38\text{ ms}$ | $98.3\text{ ms}$ |
| **Mid-Range Phone** | $0.35\times$ | $4.0\,\mu\text{s} = 0.0040\text{ ms}$ | $1.02\text{ ms}$ | $262.1\text{ ms}$ |
| **Low-End Phone** | $0.08\times$ | $15.0\,\mu\text{s} = 0.0150\text{ ms}$ | $3.84\text{ ms}$ | **$983.0\text{ ms}$** |

---

# 6. Adversary Engines & Threat Models (`src/traffic/`)

### 6.1 File Map & Responsibilities
- [`src/traffic/benign_generator.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/traffic/benign_generator.py): Weibull heavy-tailed arrival generator.
- [`src/traffic/attack_generators/asyncio_attacker.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/traffic/attack_generators/asyncio_attacker.py): High-throughput async attack suite (Stack A).
- [`src/traffic/attack_generators/locust_attacker.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/traffic/attack_generators/locust_attacker.py): Locust-profile independent generator (Stack B).
- [`src/traffic/adaptive_adversary/mimicry_attacker.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/traffic/adaptive_adversary/mimicry_attacker.py): Black-box parameter optimizer for evasion cost evaluation.
- [`src/traffic/adaptive_adversary/extraction_attacker.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/traffic/adaptive_adversary/extraction_attacker.py): Model extraction probing engine and surrogate learner.

### 6.2 Threat Model Summary
Per spec §4, we model a resource-bounded rational adversary with:
1. **Compute Resources**: Standard multi-core CPU / GPU rig ($t_{\text{hash}} = 0.8\,\mu\text{s}$).
2. **Identity Control**:
   - *Fixed Identity*: Persistent IP/fingerprint over multi-minute campaigns.
   - *Rotating Identity*: Ability to acquire new IP addresses (residential proxy pool) and rotate headers per $N$ requests.
3. **Information State (Kerckhoffs' Principle)**:
   - Full knowledge of the defense architecture, HMAC signing algorithms, and sliding window features.
   - Zero direct access to server-side weights, trees, or HMAC secret keys.

---

# 7. Metrics & Evaluation Methodology (`src/evaluation/`)

### 7.1 Attacker Cost Amplification (ACA)
Measures the multiplier by which the defense increases the adversary's resource expenditure per admitted request relative to an unprotected system. We report two complementary, unit-consistent formulations:

#### 1. Throughput / End-to-End Latency Cost Multiplier ($\text{ACA}_{\text{throughput}}$)
Evaluated relative to baseline HTTP request round-trip latency / handler processing time ($c_{\text{base}} = 0.4912\text{ ms}$):
$$\text{ACA}_{\text{throughput}} = \frac{c_{\text{base}} + \mathbb{E}[t_{\text{solve}}]}{c_{\text{base}} \times \text{Admission Rate}} = \frac{1}{\text{Admission Rate}} \left(1 + \frac{\mathbb{E}[t_{\text{solve}}]}{c_{\text{base}}}\right) \ge 1.0$$

#### 2. Pure Client Process CPU Time Multiplier ($\text{ACA}_{\text{CPU}}$)
Evaluated strictly via `time.process_time()` / `getrusage` on client process network I/O and parsing time ($c_{\text{net}} = 0.045\text{ ms}$):
$$\text{ACA}_{\text{CPU}} = \frac{c_{\text{net}} + \mathbb{E}[t_{\text{solve\_cpu}}]}{c_{\text{net}} \times \text{Admission Rate}} = \frac{1}{\text{Admission Rate}} \left(1 + \frac{\mathbb{E}[t_{\text{solve\_cpu}}]}{c_{\text{net}}}\right) \ge 1.0$$

At difficulty $d=16$, solve time is $52.43\text{ ms}$. This yields $\text{ACA}_{\text{throughput}} = 107.74\times$ and $\text{ACA}_{\text{CPU}} = 1166.08\times$.

### 7.2 Legitimate User Tax (LUT)
Measures the added end-to-end latency imposed on innocent clients, stratified by hardware capability class $c \in \{\text{laptop}, \text{mid\_phone}, \text{low\_phone}\}$:

$$\text{LUT}(c) = \text{Latency}_{\text{defense}}(c) - \text{Latency}_{\text{baseline}}$$
Reported as full empirical distributions ($p50, p95, p99$) with 95% bootstrap confidence intervals.

### 7.3 Expected Calibration Error (ECE)
Partitions predicted probabilities into $M=10$ equal-width bins $B_1, \dots, B_M$:

$$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$

---

# 8. Experimental Catalog (Phases 1–8)

All experimental numbers below were executed and verified from deterministic seeds; raw JSON traces reside in `results/raw_logs/`.

```
========================================================================================================
Phase  Target / Hypothesis              Method / Script                   Key Empirical Finding
========================================================================================================
P1     In-path gateway overhead         run_phase1_benchmark.py           Added tax: p50=0.078ms, p95=0.119ms
       must be sub-millisecond.         (N=1000 trials, seed=42)          Replay/tamper attacks: 100% rejected.

P2     Benign traffic must defeat       run_phase2_benchmark.py           Fitted Weibull (k=0.65): CV=1.572 vs
       Poisson assumption (CV > 1.5).   (N=10,000 arrivals, seed=42)      Poisson CV=0.997 (57.6% more variance).

P3     Calibration improves gating;     run_phase3_benchmark.py           Isotonic ECE=0.0010 (99.5% reduction).
       Random scoring fails equity.     (N=600 test, seed=42)             Random scoring taxes mobile by 98.3ms.
       Cross-generator gap audit.                                         Cross-gen AUC: 1.0000 -> 0.8376 (16.3% drop).

P4     Naive controller oscillates      run_phase4_benchmark.py           147 limit-cycle reversals under dt=1.5s.
       under feedback delay.            (T=60s, dt=1.5s, seed=42)         Throughput swings from 1.8 to 30.2 req/s.

P4-S   Bimodality & Bang-Bang sweep     run_phase4_sensitivity.py         Proves d*(p) is bang-bang for high B/lambda
       over 3x3 (B, lambda) grid.       (Grid B in [1..100], lam in [50]) due to 2^d * t_hash << t_base for d <= 10.

P5     EWMA + dwell time + slew limit   run_phase5_benchmark.py           Reversals cut by 87.8% (115 -> 14).
       stabilizes closed loop.          (Sweep dt in [0.1..10.0]s)        Asymptotically stable for dt <= 3.0s.

P6     Mimicry adversary pays           run_phase6_benchmark.py           Evading d=2 requires 65% decoy mix,
       measurable throughput cost.      (Sweep d_target in [2..16])       sacrificing 84.3% attack throughput.

P7     Adaptation delay suppresses      run_phase7_benchmark.py           Unmitigated extracted in <= 40 probes.
       surrogate model extraction.      (N=20 trials per Q in [10..1000]) Delay (K=10) suppresses rho to 0.231.

P8     Adaptive PoW matches d=16 ACA    run_phase8_frontier.py            Adaptive PoW: ACA_thr=107.74x, ACA_cpu=1166x,
       with 16,384x lower mobile tax.   (10 runs per arm, seed=42)        LUT=0.012ms (Pareto dominant over static d=16).
========================================================================================================
```

---

# 9. Security Assumptions & Fundamental Boundaries

### 9.1 The Identity-Rotation / Sybil Boundary
- Adaptive PoW relies on sliding-window state keyed by client identity ($k$).
- An adversary rotating identities per request forces the system into cold-start evaluation.
- Under a benign cold-start floor ($d_{\text{init}}=2$), **identity rotation completely defeats the adaptive defense** ($\text{ACA} = 1.01\times$, $99.0\%$ collapse).
- Under an aggressive cold-start floor ($d_{\text{init}}=8$), ACA is capped at $1.42\times$, but forces every first-time legitimate mobile visitor to pay an upfront $0.77\text{ ms}$ solve tax.

### 9.2 The Hardware Asymmetry Boundary
- On SHA-256, GPU hash clusters achieve $>1000\times$ speedup over mobile CPUs.
- Achieving meaningful deterrence ($>100\times$) on SHA-256 requires escalating to $d \ge 16$, which places an unviable $196.6\text{ ms}$ penalty on mobile devices if misclassified.
- Memory-hard functions (Argon2id) compress hardware asymmetry to $\sim 4\times$, but shift compute overhead to the server during solution verification.

### 9.3 The Adaptation Oracle Boundary
- Adjusting challenge difficulty based on client features turns the HTTP response code / difficulty into a side-channel oracle.
- Unmitigated fine-grained difficulty leaks the decision boundary in fewer than $40$ probes ($\rho = 0.943$).
- Mitigating the side-channel requires trading off defense precision: Randomized Jitter ($\pm 2$ bits) caps fidelity at $\rho \le 0.866$ with a $0.49\text{ bit}$ MAE precision loss; Adaptation Delay ($K=10$) suppresses fidelity to $\rho \approx 0.23$.

---

# 10. Developer & Debugging Playbook

### Scenario: *"Let's Modify the Controller"*

Suppose you want to change the EWMA smoothing coefficient from $\alpha = 0.15$ to $\alpha = 0.35$ and add a new dynamic hysteresis rule. Here is the exact lifecycle trace:

#### Step 1: Locate and Modify Controller Logic
Open [`src/worker/controller.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/controller.py).
1. `DampedController.__init__` (line 88): Modify default arguments:
   ```python
   def __init__(self, mapper=None, ewma_alpha: float = 0.35, hysteresis_up: float = 0.10, ...):
   ```
2. `DampedController.update` (line 105): Traced every time an out-of-band risk score arrives for `client_key`.
   - Lines 117–119: Applies EWMA: $\bar{p} \leftarrow \alpha p + (1-\alpha) \bar{p}$.
   - Lines 125–127: Checks dwell time cooldown ($t - t_{\text{last}} \ge t_{\text{dwell}}$).
   - Lines 130–136: Checks hysteresis threshold boundaries.
   - Lines 138–144: Slew-rate limiter clamps output: $\Delta d \le \pm 1$.

#### Step 2: Trace the Data Flow to Redis
When `DampedController.update` returns difficulty $d$:
1. The async worker in [`src/worker/stream_consumer.py`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/worker/stream_consumer.py) writes:
   ```python
   await redis.set(f"risk:{client_key}", str(assigned_difficulty), ex=300)
   ```
2. On the next incoming request for `client_key`, [`src/middleware/server.py:L140`](file:///c:/Users/ASUS/OneDrive/Desktop/PoW%20Project/src/middleware/server.py) executes:
   ```python
   cached_diff = await redis_client.get(f"risk:{client_key}")
   current_difficulty = int(cached_diff) if cached_diff else 2
   ```
3. If the request lacks a valid work credit token, the gateway mints a 401 challenge with `difficulty=current_difficulty`.

#### Step 3: Run Unit & Controller Tests
Run the dedicated controller test suite to verify no limit-cycle oscillations were introduced:
```powershell
pytest tests/test_controller.py -v
```

#### Step 4: Re-Run Closed-Loop Benchmark (Phase 5)
```powershell
python benchmarks/run_phase5_benchmark.py
```
Check `results/figures/fig2_controller_comparison.png` to verify the step response converges without chattering.

---

# 11. Reproducibility & Verification

### 11.1 Full Test Suite Execution
```powershell
pytest tests/ -v
# Expected: 16 passed in ~3.5s
```

### 11.2 End-to-End Benchmark Execution
To re-generate all empirical raw logs and publication figures from scratch:
```powershell
python benchmarks/run_phase1_benchmark.py   # Baseline latencies & Red/Green checks
python benchmarks/run_phase2_benchmark.py   # Weibull vs Poisson dispersion
python benchmarks/run_phase3_benchmark.py   # Isotonic calibration & Random ablation
python benchmarks/run_phase4_benchmark.py   # Naive controller limit-cycle oscillation
python benchmarks/run_phase4_sensitivity.py # Difficulty mapping sensitivity sweep (3x3 grid)
python benchmarks/run_phase5_benchmark.py   # Damped controller stability & lag sweep
python benchmarks/run_phase6_benchmark.py   # Mimicry adversary evasion-cost curve
python benchmarks/run_phase7_benchmark.py   # Model extraction multi-seed curves
python benchmarks/run_phase8_frontier.py   # Full Pareto Frontier sweep (Figure 1)
```
