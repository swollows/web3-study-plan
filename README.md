# Web3 보안 종합 교육 과정

> **목표**: Execution Layer부터 Consensus Layer까지 보안 취약점 패턴/사례를 학습하고 해킹 실습 → CTF 대회 준비 및 문제 제작
> **기간**: 약 3개월 (20주)
> **기반 자료**: evmresearch.io (387 페이지), osec.io, 주요 보안 도구/스킬 리포지토리, 실제 익스플로잇 PoC

---

## 교육 로드맵

```
현재 위치 (Web3 주요 인프라 사고사례 조사 완료)
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ Phase 1-2: EVM Internals + Solidity/Vyper 심화       │  ← 기초 강화 (1-2주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 3: 취약점 패턴 마스터 (269개 패턴)              │  ← 핵심 단계 (3-6주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 4: 실제 익스플로잇 분석 (18+ 사례)              │  ← 실전 감각 (7-8주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 5-6: 방어 패턴 + DeFi 프로토콜 메커니즘         │  ← 공방 이해 (9-10주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 7: Consensus Layer 보안                        │  ← 확장 영역 (11-12주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 8: ZK/L2 보안                                  │  ← 최신 영역 (13-14주)
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 9-10: CTF 실전 + 문제 제작                     │  ← 최종 목표 (15-20주)
└─────────────────────────────────────────────────────┘
```

---

## 강의자료 구성

### Phase 1-2: 기초 강화

| Phase | 주제 | 파일 | 분량 |
|-------|------|------|------|
| **Phase 1** | EVM Internals 심화 | [`phase1-evm-internals/`](./phase1-evm-internals/README.md) | 2,776줄 |
| **Phase 2** | Solidity/Vyper 언어 행동 분석 | [`phase2-solidity-vyper/`](./phase2-solidity-vyper/README.md) | 1,964줄 |

**Phase 1 핵심 내용:**
- EVM 아키텍처 (스택 기반 VM, 256비트 워드)
- CREATE2 메타모픽 공격, EXTCODESIZE 우회, delegatecall 컨텍스트
- 메모리/스토리지 모델, Transient Storage (EIP-1153)
- Yul/어셈블리 접근 제어 우회
- 실습: evm.codes, Foundry forge debug

**Phase 2 핵심 내용:**
- Solidity Panic 코드 분류, ABI 인코딩 수동 실습
- unchecked 블록 공격 표면, 정수 나눗셈 절삭
- Vyper 컴파일러 reentrancy lock 버그 (Curve Finance 해킹)
- Vyper 이중 평가 버그, 평가 순서 문제

---

### Phase 3-4: 취약점 패턴 + 실전 분석

| Phase | 주제 | 파일 | 분량 |
|-------|------|------|------|
| **Phase 3** | 취약점 패턴 마스터 (269개) | [`phase3-vulnerability-patterns/`](./phase3-vulnerability-patterns/README.md) | 4,122줄 |
| **Phase 4** | 실제 익스플로잇 분석 (18+ 사례) | [`phase4-exploit-analysis/`](./phase4-exploit-analysis/README.md) | 2,885줄 |

**Phase 3 취약점 카테고리 (15개):**

| 카테고리 | 패턴 수 | 대표 사례 |
|---------|---------|----------|
| A. Reentrancy | 15+ | The DAO ($60M), Fei/Rari, Curve |
| B. Access Control | 15+ | Ronin ($625M), Parity ($150M) |
| C. Oracle & Flash Loan | 12+ | Mango ($114M), YieldBlox ($10.86M) |
| D. Proxy & Upgrade | 20+ | Parity Wallet, Wormhole |
| E. 서명 & 암호학 | 15+ | Profanity ($160M), BLS 로그키 |
| F. ERC-20 비표준 | 20+ | fee-on-transfer, rebasing, ERC-4626 |
| G. ERC-4337 AA | 8 | counterfactual takeover, paymaster drain |
| H. Governance | 10+ | Beanstalk ($182M) |
| I. 산술 & 정밀도 | 15+ | ERC-4626 인플레이션 공격 |
| J. DoS & Griefing | 9+ | gas limit DoS, 청산 프론트러닝 |
| K. 크로스체인 & 브릿지 | 10+ | Poly Network ($611M) |
| L. Compiler Bugs | 9+ | Curve Vyper ($70M) |
| M. DeFi 구조적 | 13+ | sandwich, JIT, msg.value 이중지출 |
| N. EIP-7702 Pectra | 8 | 위임 피싱, tx.origin 우회 |
| O. 기타 | 30+ | abi.encodePacked, Merkle proof |

**Phase 4 주요 익스플로잇:**

| 사건 | 손실액 | 공격 유형 |
|------|--------|----------|
| Bybit | ~$1.5B | Supply chain (JS injection) |
| Ronin Bridge | $625M | Validator key compromise |
| Poly Network | $611M | Cross-chain selector brute-force |
| WazirX | $230M | Custody UI compromise |
| Euler Finance | $197M | Economic logic flaw |
| Beanstalk | $182M | Flash loan governance |
| Profanity | $160M+ | 32-bit seed keyspace |
| Parity Wallet | $150M | selfdestruct proxy brick |
| Mango Markets | $114M | Oracle manipulation |
| Orbit Chain | $82M | Insider threat |
| Curve Finance | ~$70M | Vyper compiler bug |
| Radiant Capital | $50M | Malware + multisig bypass |
| Penpie | $27M | Reentrancy + flash loan |

---

### Phase 5-6: 방어 + DeFi 메커니즘

| Phase | 주제 | 파일 | 분량 |
|-------|------|------|------|
| **Phase 5** | 방어 패턴 및 보안 도구 | [`phase5-defense-patterns/`](./phase5-defense-patterns/README.md) | 1,659줄 |
| **Phase 6** | DeFi 프로토콜 메커니즘 | [`phase6-defi-mechanisms/`](./phase6-defi-mechanisms/README.md) | 1,778줄 |

**Phase 5 핵심:**
- 코드/프로토콜/검증/운영 레벨 방어 패턴 48개
- 런타임 가드: 85% 익스플로잇 차단, <1% 가스 오버헤드
- 심층 방어: 87% 침해 확률 감소
- 보안 감사 도구: Slither, Aderyn, Semgrep, Certora, KEVM
- Claude Code Skills: Trail of Bits (35+), QuillShield (10), SCV-scan (36)

**Phase 6 핵심:**
- AMM (Uniswap V4 Hooks, Curve), Lending, Stablecoin
- Bridge, Perpetual DEX, RWA 토큰화
- ERC-4337 EntryPoint, ERC-7540 비동기 상환

---

### Phase 7-8: Consensus + ZK/L2

| Phase | 주제 | 파일 | 분량 |
|-------|------|------|------|
| **Phase 7** | Consensus Layer 보안 | [`phase7-consensus-layer/`](./phase7-consensus-layer/README.md) | 1,118줄 |
| **Phase 8** | ZK/L2 보안 | [`phase8-zk-l2/`](./phase8-zk-l2/README.md) | 1,275줄 |

**Phase 7 핵심:**
- Validator 보안: Slashing, BLS 키 관리, Lifecycle
- Staking/Restaking: LST 디페깅, EigenLayer, Lido 집중도
- MEV & PBS: sandwich, JIT, time-bandit, 검열 저항성
- Finality: Casper FFG, LMD-GHOST, 밸런싱 공격
- 클라이언트 다양성: Prysm/Lighthouse/Teku/Nimbus

**Phase 8 핵심:**
- zkVM Soundness: 6개 zkVM 공통 취약점 (Fiat-Shamir 바인딩 누락)
- ZK Rollup: zkEVM Type 1-4, 프로버 킬러 공격
- Optimistic Rollup: Challenge 메커니즘, Challenger 검열
- L2 거버넌스: Security Council, 업그레이드 권한

---

### Phase 9-10: CTF

| Phase | 주제 | 파일 | 분량 |
|-------|------|------|------|
| **Phase 9** | CTF 실전 훈련 | [`phase9-ctf-training/`](./phase9-ctf-training/README.md) | 814줄 |
| **Phase 10** | CTF 문제 제작 | [`phase10-ctf-creation/`](./phase10-ctf-creation/README.md) | 1,533줄 |

**Wargame 플랫폼 (난이도순):**
Ethernaut → Damn Vulnerable DeFi → EVM Puzzles → Paradigm CTF → Curta → DeFiHackLabs

**CTF 대회:**
Secureum RACE, Paradigm CTF, Blazctf, Ethernaut CTF, Code4rena, Sherlock, Immunefi, Remedy CTF

**문제 난이도:**
Easy (100-200점) → Medium (300-500점) → Hard (600-800점) → Expert (900-1000점)

---

### 리서치 자료

| 주제 | 파일 | 분량 |
|------|------|------|
| Rollup Challenge 성공 사례 조사 | [`research/rollup-challenge-success-cases.md`](./research/rollup-challenge-success-cases.md) | 404줄 |
| 버그바운티 플랫폼 + 사고 DB 가이드 | [`research/bug-bounty-and-incident-databases.md`](./research/bug-bounty-and-incident-databases.md) | 937줄 |

**Rollup Challenge 핵심 발견:**
- **Kroma (2024.04.01)** — 이더리움 롤업 역사상 최초이자 유일한 메인넷 Challenge 성공 사례
- 12명 challenger 중 1명이 `proveFault` 호출 성공 → 잘못된 Output Root 삭제
- Optimism: 2024.06 퍼미션리스 활성화 → 2024.08 취약점 발견 → 2024.09 Granite 패치
- Arbitrum BoLD: 2025.02 메인넷 퍼미션리스 검증 활성화

---

## 주차별 학습 계획

| 주차 | Phase | 핵심 주제 |
|------|-------|----------|
| 1-2주 | 1-2 | EVM opcode, Storage/Memory, Solidity/Vyper 컴파일러 |
| 3주 | 3 | Reentrancy + Access Control (30개 패턴) |
| 4주 | 3 | Oracle/Flash Loan + 산술/정밀도 (27개 패턴) |
| 5주 | 3 | Proxy/Upgrade + 서명/암호학 (35개 패턴) |
| 6주 | 3 | ERC-20 비표준 + ERC-4337 + EIP-7702 (36개 패턴) |
| 7주 | 4 | 익스플로잇 분석 (Bybit, Euler, Penpie, Curve) + PoC |
| 8주 | 4 | 익스플로잇 분석 (Ronin, Parity, dForce, Beanstalk) + PoC |
| 9주 | 5 | 방어 패턴 48개 + 보안 도구 (Slither, Foundry fuzzing) |
| 10주 | 6 | DeFi 메커니즘 (AMM, Lending, Stablecoin, Bridge) |
| 11주 | 7 | Consensus Layer 기초 (Casper FFG, Slashing) |
| 12주 | 7 | Consensus Layer 심화 (MEV/PBS, 클라이언트 다양성) |
| 13주 | 8 | zkVM Soundness + L2 시퀀서/롤업 보안 |
| 14주 | 8 | DA Layer + 브릿지 보안 + ZK 증명 시스템 |
| 15주 | 9 | Damn Vulnerable DeFi 전체 풀이 |
| 16주 | 9 | Paradigm CTF / Blazctf 과거 문제 풀이 |
| 17주 | 9 | DeFiHackLabs 실제 해킹 재현 |
| 18주 | 10 | CTF 문제 설계 (Easy/Medium) |
| 19주 | 10 | CTF 문제 설계 (Hard/Expert) |
| 20주 | 10 | Consensus + ZK 문제 설계 + 테스트 |

---

## 핵심 도구

| 분류 | 도구 |
|------|------|
| **개발/테스트** | Foundry (forge, cast, anvil), Hardhat, Huff |
| **정적 분석** | Slither, Aderyn, Semgrep |
| **형식 검증** | Certora, KEVM, Halmos |
| **퍼징** | Foundry invariant tests, Echidna, Medusa |
| **디버깅** | Foundry forge debug, Tenderly, evm.codes |
| **모니터링** | Forta, OpenZeppelin Defender |
| **CTF 인프라** | CTFd, rCTF, Docker, Anvil fork |

## 버그바운티 & 사고 DB

| 플랫폼 | 유형 | 특징 |
|--------|------|------|
| **Immunefi** | 버그바운티 | $110M+ 보상, 최대 $10M, 45K+ 연구자 |
| **Code4rena** | 경쟁 감사 | Warden 시스템, $50K-$200K 상금풀 |
| **Sherlock** | 감사 + 보험 | Lead Senior Watson |
| **Hats Finance** | 탈중앙화 | 온체인 보상 |
| **rekt.news** | 사고 DB | 해킹 리더보드 |
| **DeFiHackLabs** | PoC 재현 | Foundry 기반 실제 해킹 재현 |
| **Solodit** | 취약점 DB | 감사 보고서 검색 |
| **L2Beat** | L2 트래커 | Stage 분류, 보안 현황 |

---

## 참고 자료

| 분류 | 자료 |
|------|------|
| **핵심 연구** | [evmresearch.io](https://evmresearch.io) (387 페이지), [osec.io](https://osec.io) |
| **사양** | ethereum/consensus-specs, ethereum/execution-specs |
| **Wargame** | Ethernaut, Damn Vulnerable DeFi, EVM Puzzles, Curta |
| **CTF** | Paradigm CTF, Blazctf, Code4rena, Remedy CTF |
| **도구** | Foundry, Slither, Aderyn, Semgrep, Certora, KEVM |
| **해킹 DB** | DeFiHackLabs, rekt.news, Solodit |
| **L2 현황** | [L2Beat](https://l2beat.com/stages) |

---

> **총 강의자료**: 12개 파일, 21,265줄 | **작성일**: 2026-03-15
