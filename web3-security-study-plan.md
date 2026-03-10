# Web3 보안 종합 스터디 플랜

> **목표**: 해킹대회(CTF) 준비 및 대회 문제 제작
> **범위**: Execution Layer + Consensus Layer
> **기반 자료**: evmresearch.io (387 페이지), osec.io, 주요 보안 도구/스킬 리포지토리, 실제 익스플로잇 PoC
> **작성일**: 2026-03-10

---

## 목차

1. [현재 진도 요약 및 다음 단계 로드맵](#1-현재-진도-요약-및-다음-단계-로드맵)
2. [Phase 1: EVM Internals 심화](#2-phase-1-evm-internals-심화)
3. [Phase 2: Solidity/Vyper 언어 행동 분석](#3-phase-2-solidityvyper-언어-행동-분석)
4. [Phase 3: 취약점 패턴 마스터](#4-phase-3-취약점-패턴-마스터)
5. [Phase 4: 실제 익스플로잇 분석](#5-phase-4-실제-익스플로잇-분석)
6. [Phase 5: 방어 패턴 및 보안 도구](#6-phase-5-방어-패턴-및-보안-도구)
7. [Phase 6: DeFi 프로토콜 메커니즘](#7-phase-6-defi-프로토콜-메커니즘)
8. [Phase 7: Consensus Layer 보안](#8-phase-7-consensus-layer-보안)
9. [Phase 8: ZK/L2 보안](#9-phase-8-zkl2-보안)
10. [Phase 9: CTF 실전 훈련](#10-phase-9-ctf-실전-훈련)
11. [Phase 10: CTF 문제 제작](#11-phase-10-ctf-문제-제작)
12. [보안 감사 도구 생태계 분석](#12-보안-감사-도구-생태계-분석)
13. [추천 학습 순서 및 주차별 계획](#13-추천-학습-순서-및-주차별-계획)
14. [참고 자료 전체 링크](#14-참고-자료-전체-링크)

---

## 1. 현재 진도 요약 및 다음 단계 로드맵

### 현재 완료된 학습
- Web3 주요 인프라 개념 및 구현 사례 분석
- 과거 사고 사례에서 취약점 식별

### 다음 단계 전체 로드맵

```
현재 위치
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ Phase 1-2: EVM Internals + Solidity/Vyper 심화       │  ← 기초 강화
│ (opcode, storage, memory, 컴파일러 행동)              │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 3: 취약점 패턴 마스터 (269개 패턴)              │  ← 핵심 단계
│ (reentrancy, access control, oracle, flash loan,     │
│  EIP-7702, ERC-4337, proxy, compiler bugs...)        │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 4: 실제 익스플로잇 분석 (21개 사례)             │  ← 실전 감각
│ (Bybit, Euler, Penpie, Ronin, YieldBlox...)          │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 5-6: 방어 패턴 + DeFi 프로토콜 메커니즘         │  ← 공방 이해
│ (formal verification, fuzzing, circuit breaker,      │
│  AMM, lending, stablecoin, bridge...)                │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 7: Consensus Layer 보안                        │  ← 확장 영역
│ (validator, staking, MEV, PBS, slashing...)           │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 8: ZK/L2 보안                                  │  ← 최신 영역
│ (zkVM soundness, rollup, sequencer, DA, bridge...)   │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│ Phase 9-10: CTF 실전 + 문제 제작                     │  ← 최종 목표
│ (wargame, CTF 참가, 문제 설계, 검증)                  │
└─────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: EVM Internals 심화

> evmresearch.io/evm-internals (17 페이지)

### 2.1 실행 환경 및 Opcode

| 주제 | evmresearch 노트 | CTF 관련도 |
|------|-----------------|-----------|
| CREATE2 메타모픽 공격 | `CREATE2 enables metamorphic contract attacks by allowing a self-destructed contract to be redeployed with different bytecode at the same trusted address` | ★★★★★ |
| 크로스체인 opcode 비호환 | `EVM opcode incompatibility across chains causes failures when contracts assume uniform opcode support` | ★★★☆☆ |
| EXTCODESIZE 우회 | `EXTCODESIZE returns zero during constructor execution allowing contracts to bypass code-size-based EOA checks` | ★★★★★ |
| delegatecall 컨텍스트 | `delegatecall executes code from another contract using the callers storage context` | ★★★★★ |
| Yul division by zero | `yul division by zero returns zero rather than reverting unlike solidity checked arithmetic` | ★★★★☆ |

### 2.2 메모리 & 스토리지 모델

| 주제 | evmresearch 노트 | CTF 관련도 |
|------|-----------------|-----------|
| 커스텀 스토리지 레이아웃 | `custom storage layouts enable powerful proxy patterns but manual slot math errors can corrupt data` | ★★★★★ |
| 메모리 가스 이차 비용 | `evm memory gas costs grow quadratically making large allocations prohibitively expensive` | ★★★☆☆ |
| low-level call 사일런트 성공 | `low-level calls to non-existent contracts succeed silently because the EVM treats empty addresses as successful` | ★★★★★ |
| memory vs calldata 패킹 | `memory and calldata values are not packed unlike storage` | ★★★☆☆ |
| memory-to-memory 참조 | `memory-to-memory assignment in solidity creates references not copies enabling aliasing bugs` | ★★★★☆ |
| 스토리지 슬롯 패킹 | `solidity compiler packs multiple small values into one storage slot but writing requires reading the full slot` | ★★★★☆ |
| mapping delete 고아 데이터 | `solidity delete on mappings contained within arrays leaves orphaned data in storage` | ★★★☆☆ |
| pure 함수 STATICCALL 한계 | `solidity pure functions use STATICCALL but cannot prevent state reads at the EVM level` | ★★★☆☆ |
| 스토리지 변수 순서 가스 | `storage variable ordering affects gas costs because suboptimal ordering wastes storage slots` | ★★☆☆☆ |
| Transient Storage | `transient storage introduces new storage semantics with novel security implications` | ★★★★★ |
| Yul/어셈블리 접근 제어 우회 | `writing contract logic in yul or assembly can bypass access control mechanisms only implemented in solidity` | ★★★★★ |

### 2.3 학습 방법

1. **EVM Playground** (evm.codes)에서 각 opcode의 실제 동작 확인
2. **Foundry `forge debug`**로 트랜잭션을 opcode 레벨에서 트레이싱
3. 각 노트를 읽고 **최소 재현 코드(PoC)**를 직접 작성
4. CTF 문제화 가능한 패턴 식별: CREATE2, delegatecall, transient storage가 핵심

---

## 3. Phase 2: Solidity/Vyper 언어 행동 분석

> evmresearch.io/solidity-behaviors (10 페이지)

### 3.1 Solidity 컴파일러 행동

| 주제 | 노트 | 핵심 내용 |
|------|------|----------|
| Panic 코드 분류 | `Panic(uint256) error codes provide a formal taxonomy of compiler-inserted revert conditions` | 0x01=assert, 0x11=overflow, 0x12=div-by-zero, 0x31=pop-empty, 0x32=out-of-bounds, 0x41=alloc-too-much, 0x51=zero-init-func-ptr |
| 에러 계층 구조 | `Solidity's error hierarchy treats panics as unexpected bugs rather than expected failure modes` | panic vs revert 의미 차이, 예외 처리 설계 한계 |
| ABI 인코딩 | `abi types are not self-describing so the decoder must know the interface to interpret values` | 타입 정보 없는 바이트 해석 → 타입 혼동 공격 |
| unchecked 블록 | `gas optimization via unchecked blocks creates tension with arithmetic safety guarantees` | 가스 최적화 vs 안전성 트레이드오프 |
| private 가시성 | `private visibility in solidity only restricts contract-level access while all on-chain data remains publicly readable` | 온체인 데이터는 항상 공개 |
| selfdestruct 폐기 | `selfdestruct was deprecated in solidity 0.8.18 via eip-6049` | EIP-6780 이후 동작 변경 |
| 0.8.0 오버플로우 보호 | `solidity 0.8.0 introduced default arithmetic overflow protection making unchecked blocks the new attack surface` | unchecked가 새로운 공격 표면 |
| send/transfer 폐기 | `solidity 0.8.31 deprecates send and transfer signaling the move away from fixed gas stipend patterns` | 2300 gas 제한 패턴 종료 |
| 정수 나눗셈 절삭 | `solidity lacks floating-point types so all division rounds toward zero` | 정밀도 손실 → 자금 유출 가능 |

### 3.2 Vyper 특유 취약점 (vulnerability-patterns에서 추출)

| 주제 | 핵심 내용 |
|------|----------|
| `vyper augmented assignment evaluation order` | 증강 할당의 평가 순서가 out-of-bounds write 유발 |
| `vyper builtin function argument evaluation order` | 정의되지 않은 평가 순서 → 사이드이펙트 불예측 |
| `vyper compiler reentrancy lock storage slot bug` | v0.2.15~0.3.0에서 교차 함수 reentrancy 보호 실패 |
| `vyper compiler side effect elision` | slice/concat에 zero-length 인자 시 상태 변경 생략 |
| `vyper default function nonreentrancy decorator` | v0.3.0 이전 fallback에서 reentrancy 보호 미적용 |
| `vyper double evaluation bugs` | 가장 큰 컴파일러 CVE 클러스터 |
| `vyper eliminates entire solidity vulnerability classes` | 상속, 연산자 오버로딩, 재귀, 인라인 어셈블리 제거 |
| `vyper empty string nonreentrant key` | 빈 문자열 키로 reentrancy 체크 무효화 |
| `vyper nonreentrant decorator` | v0.4.0+ 글로벌 스토리지 락으로 교차함수 reentrancy 차단 |
| `vyper module composition` | 명시적 uses/initializes/exports로 모듈 간 상태 결합 방지 |

### 3.3 학습 방법

1. Solidity와 Vyper의 **동일 로직을 양쪽으로 구현**하여 컴파일러 출력 비교
2. **Vyper CVE 목록** 전수 분석 — Curve Finance 해킹이 대표 사례
3. ABI 인코딩/디코딩을 **수동으로 수행하는 연습** (CTF에서 자주 출제)

---

## 4. Phase 3: 취약점 패턴 마스터

> evmresearch.io/vulnerability-patterns (269 페이지) — **가장 핵심적인 영역**

### 4.1 카테고리별 분류 (총 269개 패턴)

#### A. Reentrancy 계열 (15+개)

| 패턴 | 설명 | 난이도 |
|------|------|--------|
| `reentrancy is possible whenever external calls precede state updates` | 기본 reentrancy — CEI 패턴 위반 | ★★☆☆☆ |
| `checks-effects-interactions pattern prevents reentrancy` | CEI 방어 패턴 | ★★☆☆☆ |
| `read-only reentrancy exploits view functions` | 읽기 전용 reentrancy → 다른 프로토콜의 불일치 상태 읽기 | ★★★★☆ |
| `ERC-721 safeTransferFrom and ERC-777 tokensReceived callbacks` | 표준 콜백 reentrancy | ★★★☆☆ |
| `ERC-777 tokensToSend hook enables pre-transfer reentrancy` | 전송 전 콜백 reentrancy | ★★★☆☆ |
| `ERC-777 arbitrary hook assignment via ERC-1820 registry` | 레지스트리 기반 콜백 주입 | ★★★★☆ |
| `ERC-1155 mintBatch callback creates reentrancy before valueLeft storage write` | 배치 민팅 reentrancy | ★★★★☆ |
| `hidden ERC standard callbacks create reentrancy surface` | 개발자가 인지 못하는 콜백 | ★★★★★ |
| `permissionless market registration in yield aggregators` | 보상 분배 콜백 reentrancy | ★★★★☆ |
| `reentrancy variant evolution outpaces defense adoption` | 변형 진화 분석 | ★★★★★ |
| `reentrancy attacks have caused over 500 million dollars` | 2016-2025 reentrancy 전체 역사 | ★★★☆☆ |
| `EIP-1153 TSTORE lacks the minimum gas requirement of SSTORE` | Transient storage로 낮은 가스에서 reentrancy | ★★★★★ |
| `EIP-1153 transient storage persists across call frames` | 트랜잭션 내 교차 호출 상태 누출 | ★★★★★ |
| `contract upgrade procedures create temporary vulnerability windows` | 업그레이드 중 reentrancy 보호 해제 | ★★★★☆ |
| `Fei Protocol Rari Capital exploit — incomplete reentrancy guard coverage` | 교차 함수 reentrancy 실제 사례 | ★★★★☆ |

**CTF 문제 제작 포인트**: read-only reentrancy + transient storage 조합, ERC-1820 레지스트리 악용

#### B. Access Control 계열 (15+개)

| 패턴 | 설명 |
|------|------|
| `access control vulnerabilities are the leading cause of smart contract financial losses` | 개요 — 2025년 최대 손실 원인 |
| `insufficient access control on sensitive functions` | 기본 접근 제어 미흡 |
| `tx.origin authentication is vulnerable to phishing` | tx.origin 피싱 |
| `Solidity functions without an explicit visibility modifier defaulted to public before version 0.5.0` | 레거시 가시성 문제 |
| `access control failures on UUPS _authorizeUpgrade` | UUPS 업그레이드 권한 |
| `uninitialized proxy contracts are vulnerable to re-initialization attacks` | 프록시 초기화 공격 |
| `single-step ownership transfer without confirmation` | 소유권 이전 실수 |
| `two-step ownership transfer is exploitable when step two does not verify step one` | 2단계 소유권 이전 결함 |
| `emergency governance functions bypass timelock delays` | 긴급 함수 악용 |
| `authorization mechanisms without explicit expiration` | 무기한 권한 부여 |
| `EIP-7702 delegation phishing enables persistent EOA account takeover` | **최신** EIP-7702 위임 피싱 |
| `EIP-7702 authorization tuples encode no execution scope, expiry, or call restrictions` | EIP-7702 무제한 위임 |
| `EIP-7702 invalidates pre-Pectra assumptions` | EOA 코드 실행 가능 → 기존 가정 붕괴 |

**CTF 문제 제작 포인트**: EIP-7702 위임 + tx.origin 체크 우회 조합

#### C. Oracle & Flash Loan 계열 (12+개)

| 패턴 | 설명 |
|------|------|
| `oracle manipulation and flash loan attacks are invisible to single-contract analysis` | 다중 시스템 공격 표면 |
| `flash loan oracle manipulation enables price feed attacks` | 플래시론 오라클 조작 기본 |
| `AMM spot prices are manipulable within a single transaction` | TWAP 없는 AMM 가격 위험 |
| `Chainlink minAnswer and maxAnswer price bounds` | 극단 이벤트 시 잘못된 가격 |
| `Chainlink oracle front-running` | 오라클 업데이트 샌드위치 |
| `Chainlink price feed heartbeats vary between feeds` | 피드별 업데이트 주기 차이 |
| `CLM protocols using slot0 for price-based liquidity redeployment` | slot0 조작 취약점 |
| `Curve pool spot prices from get_p() are explicitly documented as manipulable` | Curve 가격 조작 |
| `on-chain slippage calculation using Quoter contracts` | Quoter 기반 슬리피지도 조작 가능 |
| `TWAP bypass via asymmetric enforcement` | TWAP 비대칭 적용 우회 |
| `Mango Markets exploit — thin-liquidity oracle manipulation` | 실제 사례 |
| `YieldBlox PoC — SDEX liquidity 부족 자산 가격 조작 → Reflector 오라클 오염` | **2026년 2월** 최신 사례 |

**CTF 문제 제작 포인트**: 저유동성 자산 오라클 조작 + 플래시론 레버리지

#### D. Proxy & Upgrade 계열 (20+개)

| 패턴 | 설명 |
|------|------|
| `storage layout must remain consistent across proxy implementation versions` | 스토리지 레이아웃 일관성 |
| `eip-1967 reserved storage slots` | ERC-1967 표준 슬롯 |
| `eip-7201 namespaced storage` | 네임스페이스 스토리지 |
| `EIP-1822 UUPS upgrade logic in implementation enables permanent proxy bricking` | UUPS 브릭킹 |
| `EIP-2535 Diamond proxy facet storage collisions` | Diamond 패싯 충돌 |
| `CPIMP attacks exploit the gap between proxy deployment and initialization` | 배포-초기화 갭 공격 |
| `CPIMP defeats detection by layering fake ERC1967 Upgraded events` | CPIMP 탐지 회피 |
| `CPIMP self-restoration after every transaction` | CPIMP 지속성 |
| `non-atomic proxy deployment creates a front-running window` | 비원자적 배포 프론트러닝 |
| `selfdestruct in implementation contracts can permanently brick proxy systems` | 구현체 selfdestruct → 프록시 브릭 |
| `storage gap mismanagement in upgradeable base contracts` | 스토리지 갭 관리 실패 |
| `re-initialization vulnerabilities arise when upgrades inadvertently reset initialization state` | 재초기화 취약점 |
| `beacon proxy patterns share upgrade risk` | 비컨 프록시 공유 위험 |
| `function selector clashes between proxy and implementation` | 셀렉터 충돌 |
| `proxy architecture choice determines the tradeoff` | 아키텍처 선택 트레이드오프 |
| `non-atomic on-chain initialization creates a universal race condition` | 비원자적 초기화 레이스 |
| `double-delegation chains in CPIMP attacks` | 이중 위임 체인 |
| `metamorphic contract patterns remain exploitable on L2s` | L2에서의 메타모픽 공격 |
| `CREATE2 enables contract recreation at the same address with different bytecode` | CREATE2 재생성 |
| `EIP-7702 storage collision attacks` | EIP-7702 스토리지 충돌 |

**CTF 문제 제작 포인트**: CPIMP 공격 시나리오, Diamond 프록시 패싯 충돌

#### E. 서명 & 암호학 계열 (15+개)

| 패턴 | 설명 |
|------|------|
| `signature replay attacks succeed when contracts verify signatures without tracking processed message hashes` | 서명 재사용 |
| `signature malleability allows replay by computing complementary ECDSA signatures` | ECDSA 유연성 |
| `ecrecover returns address zero on invalid signatures` | address(0) 인증 |
| `ECDSA nonce reuse directly reveals the private key` | 논스 재사용 → 키 노출 |
| `cross-chain signature replay succeeds when UserOperations omit chain_id` | 크로스체인 재사용 |
| `cross-chain replay of signatures without chain_id binding` | chain_id 미바인딩 |
| `EIP-712 domain separator computed at deployment becomes stale after chain forks` | EIP-712 도메인 분리자 포크 |
| `signature expiration deadlines are necessary` | 서명 만료 필요성 |
| `BLS signature aggregation enables rogue-key attacks` | BLS 로그키 공격 |
| `biased ECDSA nonces enable lattice-based private key recovery` | 편향 논스 격자 공격 |
| `ERC-2612 permit signatures enable gasless approvals but create phishing vectors` | permit 피싱 |
| `EIP-1271 contracts without isValidSignature implementation return true via fallback` | EIP-1271 폴백 |
| `non-standard permit implementations that do not revert on signature failure` | 비표준 permit |
| `ERC-4337 signature replay across wallets` | AA 서명 재사용 |
| `Profanity vanity address generator used a 32-bit seed keyspace` | 바니티 주소 키 복원 |

**CTF 문제 제작 포인트**: ECDSA 논스 재사용 + 편향 논스 래티스 공격, BLS 로그키

#### F. ERC-20 토큰 비표준 행동 (20+개)

| 패턴 | 설명 |
|------|------|
| `the majority of deployed ERC-20 token contracts exhibit non-standard behaviors` | 비표준 ERC-20 개요 |
| `fee-on-transfer tokens enable accounting mismatch` | 수수료 토큰 회계 불일치 |
| `rebasing token supply changes create free arbitrage in AMMs` | 리베이싱 토큰 |
| `rebasing token balance increases cause accounting errors` | 리베이싱 잔액 오류 |
| `tokens with missing return values break IERC20 interface` | 반환값 없는 토큰 |
| `tokens that return false on failure instead of reverting` | false 반환 토큰 |
| `token admin blocklists can freeze protocol contracts` | 블랙리스트 토큰 |
| `tokens with per-transfer maximum caps silently revert` | 최대 전송량 제한 |
| `tokens with more than 18 decimals trigger arithmetic overflow` | 고정밀 토큰 |
| `double entry point tokens` | 이중 진입점 토큰 |
| `zero-value transfer and approval reverts` | 영값 전송 리버트 |
| `transfer amount fidelity cannot be assumed` | 전송량 충실도 불보장 |
| `cUSDCv3 max-uint256 transfer semantics` | cUSDCv3 특수 동작 |
| `non-string metadata encoding in ERC-20 tokens` | 비표준 메타데이터 |
| `low-decimal tokens reduce the minimum cost of ERC-4626 vault inflation attacks` | 저소수점 토큰 + ERC-4626 |
| `ERC-20 approval behaviors are mutually incompatible` | 승인 비호환성 |
| `ERC-20 approve front-running` | approve 프론트러닝 |
| `ERC-20 representations of native currency create double-spending` | ETH/WETH 이중 지출 |
| `ERC-20 tokens sent to contracts without callback support are permanently lost` | 영구 손실 |
| `USDT zero-first approval requirement` | USDT 영값 우선 |
| `globally pausable collateral tokens halt liquidations` | 일시정지 가능 토큰 |
| `flash-mintable tokens expose protocols` | 플래시 민팅 토큰 |
| `upgradeable proxy tokens allow token issuers to modify transfer semantics` | 업그레이더블 토큰 |
| `code injection via malicious ERC-20 token name attributes` | 토큰 이름 주입 |

**CTF 문제 제작 포인트**: fee-on-transfer + 리베이싱 + 이중진입점 토큰 조합

#### G. ERC-4337 Account Abstraction 계열 (8개)

| 패턴 | 설명 |
|------|------|
| `ERC-4337 EntryPoint singleton concentrates unconditional trust` | 단일 실패 지점 |
| `ERC-4337 accounts that revert on signature failure instead of returning SIG_VALIDATION_FAILED` | 번들러 시뮬레이션 파괴 |
| `ERC-4337 counterfactual wallet takeover` | CREATE2 salt 미바인딩 → 사전 배포 탈취 |
| `ERC-4337 gas penalty exploitation drains paymaster EntryPoint deposits` | 가스 페널티 악용 |
| `ERC-4337 multi-UserOperation bundles require manual transient storage cleanup` | 트랜지언트 스토리지 잔류 |
| `ERC-4337 paymasters deferring token collection to postOp` | postOp 리버트 시 지속 실행 |
| `ERC-4337 signature replay across wallets` | 계정 주소 미바인딩 서명 재사용 |
| `ERC-4337 malformed calldata in EntryPoint pack() functions` | 서명 후 calldata 변조 |

**CTF 문제 제작 포인트**: counterfactual wallet takeover, paymaster 드레인

#### H. Governance 공격 계열 (10+개)

| 패턴 | 설명 |
|------|------|
| `allowing governance voting and execution in the same transaction` | 플래시론 거버넌스 |
| `Beanstalk exploit — governance design itself can be the vulnerability` | 거버넌스 설계 취약점 |
| `low-participation governance votes enable protocol parameter manipulation` | 저참여 거버넌스 |
| `delegation concentration in DAO governance replicates plutocratic power` | 위임 집중 |
| `slow token accumulation attacks on governance` | 느린 축적 공격 |
| `vote buying markets make governance token acquisition economically rational` | 투표 구매 시장 |
| `veToken governance models concentrate decision-making power` | veToken 집중 |
| `OpenZeppelin TimelockController proposals remain executable indefinitely` | 타임락 무기한 실행 |
| `malicious governance proposal injection via CREATE2 and SELFDESTRUCT` | 메타모픽 프로포절 |
| `aggregator protocols capturing majority governance control` | 애그리게이터 거버넌스 |

#### I. 산술 & 정밀도 계열 (15+개)

| 패턴 | 설명 |
|------|------|
| `unchecked arithmetic blocks reintroduce overflow vulnerabilities` | unchecked 오버플로우 |
| `solidity 0.8 default checked arithmetic converts overflow from value manipulation to DoS` | 체크드 산술 → DoS |
| `solidity lacks floating-point types so all division rounds toward zero` | 정수 나눗셈 절삭 |
| `precision loss in DeFi can be weaponized to drain funds` | 정밀도 손실 무기화 |
| `rounding errors become exploitable when amplifiable through repetition` | 반복 반올림 증폭 |
| `individually safe rounding directions can produce exploitable composite errors` | 복합 반올림 오류 |
| `modular protocol architectures hide precision loss` | 모듈러 아키텍처 정밀도 은닉 |
| `multiplication before division is required in Solidity` | 곱셈 우선 규칙 |
| `division by zero in solidity always reverts even inside unchecked blocks` | div-by-zero DoS |
| `signed integer division overflow` | INT_MIN / -1 오버플로우 |
| `ERC-4626 vault share price manipulation via direct token donation` | ERC-4626 인플레이션 공격 |
| `Uniswap v3-v4 LiquidityAmounts helper rounding discrepancy` | 반올림 불일치 1 wei |
| `Newton-Raphson iterative solvers vulnerable to divergence` | AMM 불변식 솔버 발산 |
| `induction variable overflow permanently bricks loop-dependent functions` | 루프 카운터 오버플로우 |

#### J. DoS & Griefing 계열

| 패턴 | 설명 |
|------|------|
| `DoS via block gas limit permanently bricks functions` | 무제한 배열 루프 |
| `DoS via unexpected revert exploits fallback functions` | 폴백 리버트 DoS |
| `insufficient gas griefing in relayer patterns` | 릴레이어 가스 그리핑 |
| `empty array pop triggers Panic(0x31)` | 빈 배열 pop DoS |
| `attacker-controlled array indices or lengths trigger out-of-bounds panics` | 배열 OOB DoS |
| `empty array inputs bypass loop-based verification` | 빈 배열 검증 우회 |
| `borrower front-running of liquidators via tiny repayments` | 청산 DoS |
| `excessive input validation can lock funds permanently` | 과도한 검증 → 자금 락 |
| `on-chain rate limiting is undermined by Sybil attacks` | 시빌 공격 rate limit 우회 |

#### K. 크로스체인 & 브릿지 계열

| 패턴 | 설명 |
|------|------|
| `cross-chain composability breaks security assumptions` | 크로스체인 보안 가정 붕괴 |
| `cross-chain message verification is the most frequently discovered vulnerability class` | 가장 빈번한 취약점 |
| `cross-chain sandwich attacks exploit bridge event visibility` | 크로스체인 샌드위치 |
| `bridge finality assumptions create reorganization attack risk` | 최종성 가정 위험 |
| `bridge lock-and-mint architecture concentrates all locked assets` | 자산 집중 위험 |
| `bridge upgrade transactions are a distinct exploit vector` | 브릿지 업그레이드 벡터 |
| `mint-burn asymmetry in bridges enables unlimited token minting` | 민트-번 비대칭 |
| `ZK bridge verifiers are vulnerable to proof replay` | ZK 브릿지 증명 재사용 |
| `user-controlled function signatures in cross-chain dispatch — Poly Network hack` | 셀렉터 브루트포스 |
| `multi-chain deployment security requires per-chain verification` | 멀티체인 배포 검증 |

#### L. Compiler Bugs & Tooling Limitations

| 패턴 | 설명 |
|------|------|
| `compiler bugs represent a distinct threat category` | 컴파일러 버그 위협 |
| `majority of solidity 0.8.x compiler bugs manifest only under specific pipeline configurations` | 파이프라인별 버그 |
| `solidity via-IR transient storage clearing helper collision` | via-IR 트랜지언트 충돌 |
| `Curve Finance Vyper compiler exploit` | Vyper 컴파일러 reentrancy 버그 |
| `static analysis tools miss novel vulnerability patterns` | 정적 분석 한계 |
| `automated security tooling reliably detects code-level flaws but misses design-level` | 자동화 도구 한계 |
| `formal verification can only prove properties that are explicitly specified` | 명세 불완전성 |
| `property-based fuzzers systematically miss invariants` | 퍼저 한계 |
| `bytecode-level formal verification tools detect compiler-introduced vulnerabilities` | 바이트코드 검증 |

#### M. DeFi 구조적 취약점

| 패턴 | 설명 |
|------|------|
| `DeFi composability creates systemic exploit propagation risk` | 합성 가능성 → 전파 위험 |
| `protocol complexity measured in composable DeFi primitives drives vulnerability surface area nonlinearly` | 복잡성 비선형 증가 |
| `yield aggregator strategy composition inherits vulnerabilities` | 전략 합성 취약점 상속 |
| `sandwich attacks exploit AMM deterministic pricing` | 샌드위치 공격 |
| `just-in-time liquidity extraction` | JIT 유동성 추출 |
| `frontrunning exploits public mempool visibility` | 프론트러닝 |
| `missing deadline parameters allow transactions to linger in the mempool` | 데드라인 미설정 |
| `slippage protection with zero minTokensOut` | 영값 슬리피지 보호 |
| `contracts accepting both ETH and WETH must enforce mutual exclusivity` | ETH/WETH 이중계산 |
| `stale token approvals persisting after router updates` | 오래된 승인 잔류 |
| `msg.value remains constant throughout a transaction enabling double-spend when referenced inside loops` | msg.value 루프 이중지출 |
| `functions with source and destination parameters may malfunction when equal` | 동일 주소 파라미터 |
| `duplicate entries in user-supplied lists may bypass uniqueness assumptions` | 중복 항목 이중계산 |

#### N. EIP-7702 (Pectra) 신규 공격 표면 (8개)

| 패턴 | 설명 |
|------|------|
| `EIP-7702 invalidates pre-Pectra assumptions` | EOA 코드 실행 가능, ETH 전송 리버트 가능 |
| `EIP-7702 tx.origin equals msg.sender check no longer prevents flash loan attacks` | tx.origin == msg.sender 우회 |
| `EIP-7702 delegation phishing enables persistent EOA account takeover` | 위임 피싱 |
| `EIP-7702 authorization tuples encode no execution scope` | 무범위 위임 |
| `EIP-7702 delegation combined with ERC-4337 infrastructure` | 번들러/페이마스터 무비용 공격 |
| `EIP-7702 delegation does not execute the delegate contract's constructor` | 스토리지 미초기화 |
| `EIP-7702 storage collision attacks` | 위임 변경 시 스토리지 미정리 |
| `detecting EIP-7702 delegation via the 0xef0100 prefix check` (security-patterns) | 탐지 방법 |

**CTF 문제 제작 포인트**: EIP-7702는 2025-2026 최신 공격 표면으로 CTF에서 매우 유용

#### O. 기타 주요 패턴

| 패턴 | 설명 |
|------|------|
| `abi.encodePacked concatenates types shorter than 32 bytes without padding creating collision risks` | 해시 충돌 |
| `Merkle proof second-preimage attacks exploit missing domain separation` | 머클 증명 공격 |
| `inline assembly bypasses solidity safety checks` | 인라인 어셈블리 위험 |
| `inline assembly free memory pointer corruption` | 프리 메모리 포인터 손상 |
| `Solidity scratch space at memory addresses 0x00-0x3f` | 스크래치 공간 덮어쓰기 |
| `alternating between inline assembly and Solidity creates implicit state dependencies` | 어셈블리-솔리디티 교차 |
| `dangling storage references from array pop operations` | 댕글링 스토리지 참조 |
| `memory copies of storage data that are never written back` | 메모리 복사 비기록 |
| `Solidity delete on an array element zeroes the slot without reducing array length` | delete 배열 갭 |
| `incorrect inheritance ordering in Solidity multiple inheritance` | C3 선형화 문제 |
| `explicit returns from solidity modifiers do not affect function return values` | 수정자 반환값 |
| `checking default values to detect initialization is unreliable` | 기본값 초기화 검사 |
| `block timestamp manipulation within protocol bounds` | 타임스탬프 조작 |
| `block.timestamp as deadline provides no protection` | 블록 타임스탬프 데드라인 |
| `on-chain randomness from block attributes is deterministic and manipulable` | 온체인 랜덤 조작 |
| `silent semantic mismatch is a cross-language vulnerability class` | 크로스언어 의미 불일치 |
| `interface type signature mismatches produce different function selectors` | 인터페이스 셀렉터 불일치 |
| `Solidity allows casting any address to any contract interface type` | 주소-인터페이스 캐스팅 |
| `non-existent ID manipulation returns default values` | 존재하지 않는 ID |
| `state variables without explicit visibility modifier default to internal` | 기본 internal 가시성 |
| `swap-and-pop list deletion may invalidate external index references` | 스왑앤팝 인덱스 |
| `assuming contract balance equals sum of tracked deposits is unsafe` | 잔액 추적 불일치 |
| `inconsistent array length between correlated input arrays` | 배열 길이 불일치 |
| `off-by-one errors in loop bounds` | 오프바이원 |
| `EVM precompiles for BN256 never revert on invalid input` | 프리컴파일 미리버트 |
| `EVM-compatible chain precompile implementations diverge from mainnet` | 체인별 프리컴파일 차이 |
| `low-level EVM code must explicitly validate calldata input bit widths` | 콜데이터 비트폭 검증 |
| `hand-written EVM code shares a specific set of vulnerability classes` | 수작성 EVM 코드 |
| `hand-written EVM function dispatchers that lack a terminal revert` | 디스패처 폴스루 |
| `ERC-5202 blueprint contracts without preamble prefix are callable` | 블루프린트 호출 가능 |
| `ERC-7579 malicious modules can permanently lock modular smart accounts` | 모듈 언인스톨 리버트 |
| `ERC-7579 modules executing via delegatecall` | 모듈 스토리지 슬롯 덮어쓰기 |

### 4.2 OWASP Smart Contract Top 10 (2025-2026) 매핑

evmresearch.io에서 확인된 OWASP 매핑:

| 순위 | 카테고리 | 2025 → 2026 변화 | evmresearch 관련 노트 수 |
|------|---------|----------------|----------------------|
| 1 | Access Control | 최고 위험 유지 | 15+ |
| 2 | Oracle Manipulation | 유지 | 12+ |
| 3 | Logic Errors | 7위 → 3위 상승 | 20+ |
| 4 | Input Validation | 유지 | 15+ |
| 5 | Reentrancy | 유지 | 15+ |
| 6 | Unchecked External Calls | 유지 | 10+ |
| 7 | Flash Loan Attacks | 유지 | 8+ |
| 8 | Integer Overflow | 2위 → 8위 하락 (0.8.0 보호) | 5+ |
| 9 | DoS | 유지 | 9+ |
| 10 | Governance | 유지 | 10+ |

> **2026 주요 변화**: "business logic and access control together account for 78 percent of all 2025 incidents"

---

## 5. Phase 4: 실제 익스플로잇 분석

> evmresearch.io/exploit-analyses (21 페이지) + 추가 자료

### 5.1 익스플로잇 사례 전체 목록

#### Supply Chain & Infrastructure 공격 (최대 손실)

| 사건 | 핵심 메커니즘 | 손실액 |
|------|-------------|--------|
| **Bybit 해킹** | JavaScript 주입 → 웹 기반 서명 인프라 우회 → 하드웨어 월렛 보호 무력화 | ~$1.5B |
| **Ronin Bridge** | 브릿지 밸리데이터 세트 장악 → 인가되지 않은 메시지 릴레이 | $625M |
| **WazirX** | 커스토디 UI 장악 → 유효한 다중서명 수집 → 악성 컨트랙트 업그레이드 | $230M |
| **Radiant Capital** | 멀웨어 → Gnosis Safe 서명 요청 가로채기 → 3/11 다중서명 우회 | $50M |
| **Orbit Chain** | 내부자 위협 — 퇴사 전 방화벽 정책 의도적 약화 → 시한부 브릿지 악용 | $82M |
| **DPRK 위협 행위자** | 스마트 컨트랙트 악용 → 소셜 엔지니어링/인프라 장악/공급망 공격으로 전환 | 수조원 |
| **Profanity** | 32비트 시드 → 모든 생성 개인키 복원 가능 | $160M+ |

#### 스마트 컨트랙트 로직 공격

| 사건 | 핵심 메커니즘 | 관련 패턴 |
|------|-------------|----------|
| **Euler Finance** | `donateToReserves` 경제 로직 결함 — 자동화 도구 전체 미탐지 | 경제 로직 |
| **Penpie** | 무허가 Pendle 마켓 생성 → reentrancy → 플래시론 증폭 $27M 추출 | reentrancy + 플래시론 |
| **Furucombo** | 무제한 delegatecall → 스토리지 승인 조작 | delegatecall |
| **Parity Wallet** | 구현체 selfdestruct → 프록시 영구 브릭 | proxy + selfdestruct |
| **SushiSwap RouteProcessor2** | 미검증 사용자 주소 콜백 → 위임 실행 컨텍스트 | 콜백 + 접근제어 |
| **USPD** | 공개된 배포 취약점을 자체 감사 없이 적용 | 배포 프로세스 |
| **yETH** | 풀 드레인 후 스테일 캐시 → 부트스트랩 재진입으로 무제한 토큰 민팅 | 상태 캐시 + reentrancy |
| **Bunni** | 개별 안전한 반올림 방향이 다중 연산 합성 시 악용 가능 | 정밀도 합성 |
| **dForce** | Curve `get_virtual_price` read-only reentrancy → 인위적 청산 | read-only reentrancy |
| **Beanstalk** | 거버넌스 설계 자체가 취약점 — 컨트랙트는 정상 동작 | 거버넌스 |
| **Mango Markets** | 저유동성 오라클 조작 + 미실현 PnL 담보 → 프로토콜 전체 드레인 | 오라클 + 경제 로직 |
| **Self-liquidation via flash loan** | 플래시론으로 자기 청산 트리거 → 청산 보상 수취 | 플래시론 |
| **ERC-4337 pack() calldata mutation** | 서명 후 UserOperation 필드 변조 → 페이마스터 의도 위반 | AA |

### 5.2 추가 분석 자료: YieldBlox $10.86M PoC (2026년 2월)

> 출처: https://github.com/DK27ss/YieldBlox-10M-PoC

- **체인**: Stellar
- **프로토콜**: Blend V2 - YieldBlox DAO Pool
- **손실**: ~$10.86M (XLM 61.25M + USDC 1M)
- **근본 원인**: SDEX 저유동성 USTRY/XLM 가격 100배 조작 → Reflector 오라클 오염
- **공격 흐름**:
  1. SDEX에서 USTRY 가격 $1.06 → $106.74로 조작 (ask측 5 USTRY 미만)
  2. Reflector 오라클이 조작 가격 흡수
  3. 오라클 어댑터가 최신 오염 가격만 반환
  4. 과대평가된 USTRY 담보로 USDC $1M + XLM 61.25M 차입
  5. 헬스팩터: 조작 기준 1.36 (통과) vs 실제 기준 0.013 (거부되어야 함)
- **교훈**: 오라클 소스의 유동성 검증 필수, 가격 변동 상한선 필요

### 5.3 학습 방법

1. 각 사건의 **실제 트랜잭션을 Etherscan/block explorer에서 추적**
2. Foundry fork 테스트로 **PoC 재현**
3. **근본 원인 → 방어책 → 우회법** 3단계 분석
4. 사건별 **1페이지 요약 + PoC 코드** 작성

---

## 6. Phase 5: 방어 패턴 및 보안 도구

> evmresearch.io/security-patterns (48 페이지)

### 6.1 방어 패턴 분류

#### 코드 레벨 방어

| 패턴 | 설명 | 적용 대상 |
|------|------|----------|
| `SafeERC20 resolves token return value incompatibility` | 반환값 호환 래퍼 | ERC-20 비표준 |
| `OpenZeppelin Initializable with initializer modifier` | 재초기화 방지 | 프록시 |
| `restricting delegatecall to pre-verified logic contracts` | delegatecall 제한 | 프록시 |
| `atomic proxy deployment` | 원자적 배포+초기화 → CPIMP 차단 | 프록시 |
| `eip-1967 reserved storage slots` | 프록시 스토리지 슬롯 예약 | 프록시 |
| `eip-7201 namespaced storage` | 네임스페이스 충돌 방지 | 업그레이더블 |
| `multiplication before division` | 정밀도 손실 최소화 | 산술 |
| `locking pragma versions` | 테스트되지 않은 컴파일러 방지 | 컴파일러 |
| `double hashing Merkle leaves` | 2차 역상 공격 방지 | 머클트리 |
| `RFC 6979 deterministic nonce generation` | ECDSA 키 노출 방지 | 서명 |
| `proof of possession prevents BLS rogue-key attacks` | BLS 로그키 방지 | BLS |
| `detecting EIP-7702 delegation via 0xef0100 prefix` | EIP-7702 탐지 | 신규 |
| `EIP-6780 restricts SELFDESTRUCT` | 메타모픽 패턴 제거 | L1 |

#### 프로토콜 레벨 방어

| 패턴 | 설명 |
|------|------|
| `circuit breakers provide independent security guarantees` | 서킷 브레이커 |
| `ERC-7265 on-chain circuit breakers are fundamentally reactive` | 한계: 최초 공격 차단 불가 |
| `combined runtime invariant guards block 85 percent of exploits with less than 1 percent gas overhead` | 런타임 불변식 가드 |
| `balance invariants requiring sum of user balances equals total supply` | 잔액 불변식 |
| `EOA access control invariant is the single most effective runtime exploit guard` | EOA 접근 제어 |
| `defense-in-depth combining pre/post-deployment security layers reduces breach by 87%` | 심층 방어 |
| `timelocks on contract ownership transfers` | 타임락 |
| `emergency pause multisig threshold of 50 to 70 percent` | 긴급 정지 임계값 |
| `snapshot-based voting power measurement` | 플래시론 거버넌스 방지 |
| `rage quit mechanisms give token holders a credible exit threat` | 거버넌스 탈출 메커니즘 |
| `commit-reveal schemes prevent frontrunning` | 커밋-리빌 |
| `token-level transfer cooldowns break sandwich attack atomicity` | 전송 쿨다운 |
| `DeFi protocols on L2 must check L2 sequencer uptime before consuming Chainlink price feeds` | L2 시퀀서 업타임 검사 |
| `post-deployment verification by directly reading ERC1967 implementation storage slots` | 배포 후 검증 |

#### 검증 & 테스팅 방어

| 패턴 | 설명 |
|------|------|
| `formal verification and fuzzing find systematically different bug classes` | FV + 퍼징 상보적 |
| `formal verification finds bugs that all three major fuzzers miss` | FV 고유 발견 |
| `formally rare bugs requiring inputs with probability below 1 in 2^80 are unreachable by fuzzers` | FV 고유 영역 |
| `formal verification proves code matches a specification but cannot prove the specification itself is complete` | FV 한계 |
| `formal verification completeness paradox — 92% post-audit exploit rate` | 명세 불완전성 패러독스 |
| `KEVM provides complete executable formal semantics of the EVM` | KEVM 형식 의미론 |
| `writing correct invariants constitutes 80 percent of verification work` | 불변식 작성이 80% |
| `combining multiple security analysis tools detects more unique vulnerabilities` | 다중 도구 조합 |
| `testing smart contracts with specification languages different from implementation` | 교차 언어 테스트 |
| `handler functions in invariant fuzz tests must satisfy preconditions` | 퍼저 핸들러 설계 |
| `calling a function X times with value Y should equal calling it once with value XY` | 반복 불변식 |
| `complementary function pairs that don't mirror all state mutations` | 대칭성 퍼징 |
| `invariant analysis as a systematic audit methodology` | 불변식 감사 방법론 |
| `bug heuristic methodology combines code patterns easy to get wrong with high-impact targets` | 버그 휴리스틱 |
| `developer subconscious assumptions about prior state create systematic input validation gaps` | 개발자 무의식 가정 |

#### 보안 감사 & 운영

| 패턴 | 설명 |
|------|------|
| `92% of smart contracts exploited in 2025 had passed security reviews` | 감사 한계 |
| `audit coverage expires when protocol assumptions change after the audit` | 감사 만료 |
| `automated security tools combined catch approximately 60 percent` | 자동화 60%, 인간 40% |
| `off-chain transaction monitoring detects holistic attack patterns` | 오프체인 모니터링 |
| `governance systems must verify proposal code integrity at execution time` | 거버넌스 코드 검증 |
| `state transition invariants preventing invalid progression` | 상태 전이 불변식 |

### 6.2 핵심 통계

- **런타임 가드**: 85% 익스플로잇 차단, 1% 미만 가스 오버헤드
- **심층 방어**: 사전+사후 배포 계층 → 침해 확률 87% 감소
- **2025년 감사 통과 후 해킹**: 92% — 명세 완전성이 코드 정확성보다 중요
- **자동화 도구**: 60% 탐지, 나머지 40%는 경제 모델링 + 합성 추론 인간 전문성 필요
- **FV vs 퍼징**: 체계적으로 다른 버그 클래스 발견, 최소 중복 → 상보적

---

## 7. Phase 6: DeFi 프로토콜 메커니즘

> evmresearch.io/protocol-mechanics (19 페이지)

### 7.1 프로토콜별 보안 메커니즘

| 프로토콜/표준 | 보안 주제 | 설명 |
|-------------|---------|------|
| **Uniswap V4** | Hook reentrancy | `hooks introduce arbitrary external code execution into pool swap paths` |
| **Uniswap V4** | 수수료 이중계산 | `modifyLiquidity callerDelta bundles accrued fees with principal` |
| **Concentrated Liquidity AMM** | IL 증폭 | `amplify impermanent loss within active price ranges` |
| **CLAM Tick 경계** | 이중계산/수수료 오류 | `tick boundary edge cases produce double-counting` |
| **Chainlink PoR** | 보유량 검증 | `Proof of Reserve oracle feeds provide on-chain verification` |
| **ERC-3643 T-REX** | 허가 토큰 | `permissioned token standard prevents unauthorized transfers` |
| **ERC-4337 EntryPoint** | 단일 실패점 | `singleton concentrates unconditional trust` |
| **ERC-7540** | 비동기 상환 | `asynchronous redemption vaults prevent bank-run failure modes` |
| **L2 보안 위원회** | 업그레이드 권한 | `security council governance tradeoff` |
| **Lido** | 스테이킹 집중 | `29 percent of staked ETH approaches consensus attack threshold` |
| **RWA 복구 에이전트** | burn-and-remint | `must be protected by multisig and timelock` |
| **RWA 토큰화** | 법적 래퍼 실패 | `off-chain legal wrapper failure risk` |
| **Perpetual DEX** | 오라클 모델 독성 흐름 | `expose liquidity providers to toxic flow from informed traders` |
| **Stablecoin** | 삼중 딜레마 | `no design simultaneously achieves decentralization stability and capital efficiency` |
| **zkEVM** | 타입 분류 | `type classification determines compatibility-performance tradeoff` |
| **DA 공격** | 프로버 킬러 | `DA-saturation and prover killer attacks exploit mismatches between EVM gas and ZK proving costs` |
| **Bridge 업그레이드** | 검증 임계값 버그 | `bridge upgrade transactions are a distinct exploit vector` |
| **커밋-리빌** | 프론트러닝 방지 | `concealing transaction details until after ordering is fixed` |
| **전송 쿨다운** | 샌드위치 방지 | `token-level transfer cooldowns break sandwich attack atomicity` |

### 7.2 학습 방법

1. 각 프로토콜의 **핵심 불변식**을 먼저 식별
2. 불변식이 깨지는 **경계 조건**을 탐색
3. Foundry fork 테스트로 **실제 프로토콜 상태에서 공격 시뮬레이션**
4. Uniswap V4 Hooks가 가장 CTF-friendly한 소재

---

## 8. Phase 7: Consensus Layer 보안

> evmresearch.io 범위를 넘어서는 영역 — 추가 조사 기반

### 8.1 Consensus Layer 공격 표면 분류

```
Consensus Layer 보안
├── Validator 보안
│   ├── Slashing 조건 분석
│   ├── 밸리데이터 키 관리
│   ├── 이중 서명 / 이중 투표
│   └── 강제 종료 시나리오
│
├── Staking & Restaking 보안
│   ├── Liquid Staking Token (LST) 디페깅
│   │   └── evmresearch: "LST depeg risk creates liquidation cascades"
│   ├── Restaking 복합 슬래싱
│   │   └── evmresearch: "restaking compounds validator slashing risk"
│   ├── AVS 슬래싱 논리
│   │   └── evmresearch: "AVS-defined slashing conditions can slash honest operators"
│   └── Lido 집중도 → 합의 공격 임계값
│       └── evmresearch: "Lido's concentration at 29 percent approaches threshold"
│
├── MEV & PBS
│   ├── 프로포저-빌더 분리 (PBS) 구조
│   ├── MEV 추출 메커니즘
│   ├── 시간 조작 공격 (time-bandit attack)
│   ├── 블록 재정렬 공격
│   └── 검열 저항성
│
├── Finality & Fork Choice
│   ├── LMD-GHOST / Casper FFG 분석
│   ├── 최종성 지연 공격
│   ├── 밸런싱 공격 (balancing attack)
│   ├── 롱레인지 공격
│   └── 아발란치 공격
│
├── P2P 네트워킹
│   ├── Eclipse 공격
│   ├── 이클립스를 통한 합의 분할
│   ├── Gossip 프로토콜 스팸
│   └── 노드 도스 공격
│
└── 클라이언트 다양성
    ├── 단일 클라이언트 버그의 합의 실패 위험
    ├── Prysm/Lighthouse/Teku/Nimbus 차이
    └── 슈퍼마이너리티 클라이언트 버그의 슬래싱 위험
```

### 8.2 Consensus Layer 핵심 학습 주제

| 주제 | 세부 내용 | CTF 관련도 |
|------|----------|-----------|
| **Casper FFG Finality** | 정당성(Justification) → 최종성(Finalization) 메커니즘, 2/3 초과 다수결 | ★★★★★ |
| **LMD-GHOST Fork Choice** | 최근 메시지 기반 포크 선택 규칙, 투표 조작 | ★★★★☆ |
| **Validator Lifecycle** | 입금 → 활성화 → 탈퇴 → 출금, 각 단계별 공격 표면 | ★★★★☆ |
| **Slashing 조건** | 이중 투표, 서라운딩 투표, 제안자 슬래싱, 상관관계 페널티 | ★★★★★ |
| **Proposer-Builder Separation** | 블록 빌더 → 프로포저 분리, MEV 경매 메커니즘 | ★★★★☆ |
| **Attestation 메커니즘** | 에폭/슬롯 구조, 위원회 배정, 집계 | ★★★☆☆ |
| **Sync Committee** | 라이트 클라이언트 프로토콜, 서명 집계 | ★★★★☆ |
| **Validator Key Management** | BLS-12-381, 서명키 vs 출금키 분리 | ★★★★★ |
| **Beacon Chain State Transition** | 상태 전이 함수 분석 | ★★★★☆ |
| **Withdrawal 메커니즘** | EIP-4895 이후 출금 프로세스 | ★★★☆☆ |

### 8.3 Consensus Layer CTF 문제 유형

1. **BLS 서명 공격**: 로그키 공격, 논스 재사용, 편향 논스 (evmresearch 노트 연결)
2. **Fork Choice 조작**: 밸런싱 공격 시뮬레이션
3. **Slashing 조건 분석**: 상관관계 페널티 극대화 시나리오
4. **MEV 추출**: 샌드위치, JIT, 시간 조작 시뮬레이션
5. **클라이언트 다양성**: 특정 클라이언트 버그를 통한 합의 분할

### 8.4 학습 자료

- **eth2book.info**: Consensus Layer 사양 해설
- **ethereum/consensus-specs**: 공식 사양 (Python)
- **ethereum/annotated-spec**: 주석 달린 사양
- **Beacon Chain explainer (Ethereum Foundation)**
- **PBS 관련**: MEV-Boost, Flashbots 문서

---

## 9. Phase 8: ZK/L2 보안

### 9.1 OSecure zkVM 분석 (2026년 3월)

> 출처: https://osec.io/blog/2026-03-03-zkvms-unfaithful-claims/

**6개 zkVM 시스템에서 동일 근본 원인의 취약점 발견:**

| 시스템 | 취약점 | 영향 | 수정일 |
|--------|--------|------|--------|
| **Jolt** | opening_claims 트랜스크립트 미흡수 | sumcheck 결과 조작 | 2025-10-03 |
| **Nexus** | claimed_sum 미흡수 | logup 검증 우회 | 2025-10-24 |
| **Cairo-M** | public_data 미흡수 | 메모리/레지스터 위조 | 2025-10-31 |
| **Ceno** | out_evals 미흡수 | 다항식 합 조작 | 미해결 |
| **Expander** | public_input 미흡수 | 입출력 조작 | 2026-01-21 |
| **Binius64** | public witness 미흡수 | 비트 연산 위조 | 2025-12-29 |

**핵심 공격 메커니즘**:
- 프로버 제어 값이 Fiat-Shamir 챌린지 생성 전에 트랜스크립트에 흡수되지 않음
- 검증 방정식이 선형: `α·V + β = target` → 해: `V = (target - β)/α`
- 챌린지를 먼저 본 후 역계산 가능 → **거짓 증명 수용**

**근본 원인 분석**:
1. 학술 논문이 비상호작용화(Fiat-Shamir) 세부사항 생략
2. 다계층 설계에서 바인딩 책임 회피
3. 성능(해시 비용) 압박으로 "안전해 보이는" 값 제외
4. 정직한 프로버로만 테스트 → 적대적 입력 미발견

**보안 원칙**: "When in doubt, absorb it"

### 9.2 L2/ZK 보안 주제 (evmresearch 연결)

| 주제 | evmresearch 노트 |
|------|-----------------|
| zkEVM 타입 분류 | `zkEVM type classification determines compatibility-performance tradeoff` |
| ZK 롤업 건전성 버그 | `ZK rollup soundness bugs represent the primary failure mode` |
| ZK 브릿지 증명 재사용 | `ZK bridge verifiers are vulnerable to proof replay` |
| DA 포화 / 프로버 킬러 | `DA-saturation and prover killer attacks exploit mismatches between EVM gas and ZK proving costs` |
| L2 시퀀서 중앙화 | `L2 sequencer centralization creates systemic liveness censorship and regulatory risks` |
| L2 업그레이드 권한 | `L2 upgrade authority creates a security council governance tradeoff` |
| 옵티미스틱 롤업 챌린지 | `optimistic rollups can finalize invalid state when all challengers are censored` |
| 강제 포함 메커니즘 | `forced inclusion mechanisms in optimistic rollups are insufficient against sequencer state manipulation` |
| 메타모픽 L2 | `metamorphic contract patterns remain exploitable on L2s that have not adopted EIP-6780` |
| EVM 체인간 opcode 비호환 | `EVM opcode incompatibility across chains` |
| 프리컴파일 구현 차이 | `EVM-compatible chain precompile implementations diverge from mainnet` |

### 9.3 ZK/L2 CTF 문제 유형

1. **zkVM Soundness**: Fiat-Shamir 트랜스크립트 바인딩 누락으로 거짓 증명 생성
2. **DA Layer**: 프로버 킬러 — EVM 가스 vs ZK 증명 비용 불일치 악용
3. **롤업 탈출**: 시퀀서 검열 하에서 강제 포함으로 자금 탈출
4. **브릿지 증명 재사용**: public input 미바인딩으로 증명 재전송
5. **L2 특수 동작**: EIP-6780 미적용 L2에서 메타모픽 공격

---

## 10. Phase 9: CTF 실전 훈련

### 10.1 Wargame 플랫폼 (난이도순)

| 플랫폼 | 난이도 | 특징 |
|--------|--------|------|
| **Ethernaut** (OpenZeppelin) | ★★☆☆☆ | 기초 취약점 23문제 |
| **Damn Vulnerable DeFi** | ★★★☆☆ | DeFi 특화 18문제 |
| **Capture The Ether** | ★★☆☆☆ | 퍼즐 형태 |
| **EVM Puzzles** | ★★★☆☆ | 순수 opcode/bytecode |
| **Paradigm CTF** (과거 문제) | ★★★★☆ | 고난이도 + 창의적 |
| **Curta** | ★★★★☆ | 온체인 퍼즐 |
| **Huff Puzzles** | ★★★★☆ | 저수준 EVM |
| **Mr Steal Yo Crypto** | ★★★★☆ | DeFi 실전 시나리오 |
| **DeFiHackLabs** | ★★★★★ | 실제 해킹 사건 재현 |

### 10.2 CTF 대회

| 대회 | 특징 | 난이도 |
|------|------|--------|
| **Secureum RACE** | 보안 지식 퀴즈 (감사자 훈련) | ★★★☆☆ |
| **Paradigm CTF** | 가장 권위 있는 블록체인 CTF (과거형) | ★★★★★ |
| **Blazctf** | Paradigm 스타일 | ★★★★★ |
| **Ethernaut CTF** | OpenZeppelin 주최 | ★★★★☆ |
| **Code4rena contests** | 실전 감사 대회 | ★★★★☆ |
| **Sherlock contests** | 실전 감사 + 자금 보상 | ★★★★☆ |
| **Immunefi** | 버그 바운티 (CTF 형식 아님) | ★★★★★ |
| **Remedy CTF** | 가장 최근에 열린 블록체인 Only CTF (과거형) | ★★★★★ |

### 10.3 CTF 풀이 전략

```
문제 분석 프레임워크:
1. 컨트랙트 구조 매핑 (상속, 프록시, 외부 호출)
2. 자금 흐름 추적 (입금 → 처리 → 출금)
3. 불변식 식별 → 깨는 방법 탐색
4. 공격 벡터 열거:
   ├── reentrancy (모든 외부 호출 지점)
   ├── access control (모든 public/external 함수)
   ├── oracle/price (가격 의존 로직)
   ├── arithmetic (정밀도, 오버플로우)
   ├── signature (재사용, 위조)
   └── flash loan (레버리지)
5. PoC 작성 (Foundry test)
6. 최적화 (가스, 단계 축소)
```

---

## 11. Phase 10: CTF 문제 제작

### 11.1 문제 설계 원칙

1. **단일 핵심 취약점**: 하나의 주요 취약점 + 보조적 기술 장벽
2. **현실성**: evmresearch.io의 실제 취약점 패턴 기반
3. **유일한 풀이**: 의도된 해법이 명확하되 우회 불가
4. **점진적 난이도**: 발견 → 이해 → 익스플로잇의 3단계
5. **교육적 가치**: 풀이 후 실전 감사에 적용 가능한 통찰

### 11.2 난이도별 문제 유형 설계

#### Easy (100-200점)

| 카테고리 | 문제 아이디어 | evmresearch 기반 |
|---------|-------------|-----------------|
| Reentrancy | 기본 CEI 위반 + ERC-721 콜백 | `reentrancy is possible whenever external calls precede state updates` |
| Access Control | public 함수 + tx.origin 체크 | `tx.origin authentication is vulnerable to phishing` |
| Arithmetic | unchecked 블록 오버플로우 | `unchecked arithmetic blocks reintroduce overflow vulnerabilities` |
| Signature | ecrecover address(0) 반환 | `ecrecover returns address zero on invalid signatures` |

#### Medium (300-500점)

| 카테고리 | 문제 아이디어 | evmresearch 기반 |
|---------|-------------|-----------------|
| Read-only Reentrancy | Curve get_virtual_price 스테일 상태 읽기 | `read-only reentrancy exploits view functions` |
| ERC-4626 Inflation | 저소수점 토큰 + 직접 토큰 기부 → 쉐어 조작 | `ERC-4626 vault share price manipulation via direct token donation` |
| Flash Loan | 오라클 조작 + AMM 가격 피드 | `AMM spot prices are manipulable within a single transaction` |
| Proxy | 스토리지 레이아웃 충돌 + 업그레이드 | `storage layout must remain consistent across proxy implementation versions` |
| ERC-20 Weird | fee-on-transfer + 이중진입점 토큰 | `double entry point tokens` + `fee-on-transfer tokens` |

#### Hard (600-800점)

| 카테고리 | 문제 아이디어 | evmresearch 기반 |
|---------|-------------|-----------------|
| CPIMP | 프록시 배포-초기화 갭 + 이중 위임 체인 | `CPIMP attacks exploit the gap between proxy deployment and initialization` |
| Cross-chain | 크로스체인 서명 재사용 + chain_id 미바인딩 | `cross-chain replay of signatures without chain_id binding` |
| Governance | 플래시론 + 동일 TX 투표+실행 + 메타모픽 프로포절 | `allowing governance voting and execution in the same transaction` |
| Compiler | Vyper 이중 평가 버그 재현 | `vyper double evaluation bugs form the largest cluster of compiler CVEs` |
| AA | ERC-4337 counterfactual takeover + paymaster drain | `ERC-4337 counterfactual wallet takeover` |

#### Expert (900-1000점)

| 카테고리 | 문제 아이디어 | evmresearch 기반 |
|---------|-------------|-----------------|
| EIP-7702 + AA | 위임 피싱 → EOA 탈취 → 번들러 무비용 실행 | `EIP-7702 delegation combined with ERC-4337 infrastructure` |
| ZK Soundness | Fiat-Shamir 트랜스크립트 미바인딩 → 거짓 증명 | osec.io zkVM 분석 |
| Transient Storage | EIP-1153 교차 호출 상태 누출 + reentrancy | `EIP-1153 transient storage persists across call frames` |
| Multi-protocol | DeFi 합성 가능성 → 캐스케이드 실패 | `DeFi composability creates systemic exploit propagation risk` |
| Consensus | BLS 로그키 + Sync Committee 서명 위조 | `BLS signature aggregation enables rogue-key attacks` |

### 11.3 Consensus Layer CTF 문제 설계

| 난이도 | 문제 유형 | 설명 |
|--------|---------|------|
| Medium | **Slashing Analyzer** | 밸리데이터 증거(attestation) 데이터에서 이중 투표/서라운딩 투표 식별 |
| Hard | **Fork Choice Manipulation** | 조작된 attestation으로 잘못된 체인 헤드 선택 유도 |
| Hard | **MEV Extraction** | PBS 환경에서 최적 블록 구성을 통한 MEV 최대화 |
| Expert | **Consensus Split** | 클라이언트 구현 차이를 이용한 네트워크 분할 시뮬레이션 |
| Expert | **Restaking Slashing** | AVS 슬래싱 로직 버그 → 정직한 밸리데이터 손실 유도 |

### 11.4 문제 제작 기술 스택

```
문제 제작 인프라:
├── Foundry (솔리디티 문제 + 테스트)
├── Huff (저수준 EVM 문제)
├── Python + consensus-specs (컨센서스 문제)
├── Circom / Halo2 (ZK 문제)
├── Docker (환경 격리)
├── CTFd / rCTF (대회 플랫폼)
└── Anvil (로컬 체인 포크)

문제 검증 체크리스트:
□ 의도된 풀이가 동작하는가?
□ 비의도적 풀이(unintended solution)가 없는가?
□ 난이도가 적절한가? (테스터 검증)
□ 힌트 구조가 점진적인가?
□ 배포 스크립트가 재현 가능한가?
□ 플래그 추출이 명확한가?
```

---

## 12. 보안 감사 도구 생태계 분석

### 12.1 Claude Code Skills 비교

| 리포지토리 | 개발자 | 스킬 수 | 핵심 특징 | 라이선스 |
|-----------|--------|---------|----------|---------|
| **[pashov/skills](https://github.com/pashov/skills)** | Pashov Audit Group | 1 | `solidity-auditor` — 5분 이내 빠른 보안 피드백 | MIT |
| **[trailofbits/skills](https://github.com/trailofbits/skills)** | Trail of Bits | 35+ | 가장 포괄적 — 스마트 컨트랙트, 감사, 악성코드, 검증, RE, 모바일, 인프라 | CC-BY-SA 4.0 |
| **[Cyfrin/solskill](https://github.com/Cyfrin/solskill)** | Cyfrin / Patrick Collins | 1 | 프로덕션급 Solidity 작성 가이드, 자연어 요청 지원 | AGPL-3.0 |
| **[kadenzipfel/scv-scan](https://github.com/kadenzipfel/scv-scan)** | kadenzipfel | 1 | 36개 취약점 유형 기반 4단계 감사 워크플로우 | - |
| **[quillai-network/qs_skills](https://github.com/quillai-network/qs_skills)** | QuillShield | 10 | OWASP Top 10 완전 커버, 베이지안 신뢰도 점수 | MIT |
| **[Archethect/sc-auditor](https://github.com/Archethect/sc-auditor)** | Archethect | 4 MCP 도구 + 1 스킬 | Slither + Aderyn + Solodit + Cyfrin 체크리스트 통합 | - |

### 12.2 Trail of Bits Skills 상세 (가장 포괄적)

**스마트 컨트랙트 보안 (2개)**:
- `building-secure-contracts`: 6개 블록체인 취약점 스캐너
- `entry-point-analyzer`: 상태 변경 진입점 식별

**코드 감사 (13개)**:
- `agentic-actions-auditor`: GitHub Actions AI 에이전트 보안
- `audit-context-building`: 초세분화 아키텍처 분석
- `differential-review`: Git 이력 기반 보안 코드 리뷰
- `fp-check`: 오탐 확인 게이트
- `insecure-defaults`: 취약 기본 설정 탐지
- `semgrep-rule-creator` / `semgrep-rule-variant-creator`: Semgrep 규칙 생성
- `sharp-edges`: 위험 API/설정 식별
- `static-analysis`: CodeQL, Semgrep, SARIF 파싱
- `supply-chain-risk-auditor`: 공급망 감사
- `testing-handbook-skills`: 퍼저, 커버리지
- `variant-analysis`: 유사 취약점 발견
- `burpsuite-project-parser`: Burp Suite 파싱

**검증 (4개)**:
- `constant-time-analysis`: 타이밍 측채널 탐지 (ML-DSA 실제 발견 사례)
- `property-based-testing`: 속성 기반 테스트
- `spec-to-code-compliance`: 명세-코드 준수 검사
- `zeroize-audit`: 시크릿 영점화 감사

### 12.3 QuillShield 10대 분석 기술

1. **Behavioral State Analysis (BSA)** — 행동 의도 추출 + 적대적 시뮬레이션 + 베이지안 신뢰도
2. **Semantic Guard Analysis** — require/modifier 우회 함수 탐지
3. **State Invariant Detection** — 수학적 관계 자동 추론 (합계, 보존, 비율, 단조성)
4. **Reentrancy Pattern Analysis** — 모든 변형 탐지 + CEI 검증
5. **Oracle & Flash Loan Analysis** — 오라클 조작/플래시론 벡터 탐지
6. **Proxy & Upgrade Safety** — 4가지 프록시 패턴 검증
7. **Input & Arithmetic Safety** — 정밀도 손실, ERC-4626 인플레이션
8. **External Call Safety** — Weird ERC20, 콜백 위험
9. **Signature & Replay Analysis** — 5가지 재생 공격 유형
10. **DoS & Griefing Analysis** — 63/64 가스 그리핑, 스토리지 블로트

### 12.4 scv-scan 36개 취약점 체크시트

4단계 감사 워크플로우:
1. **체크시트 로드**: 36개 취약점 클래스의 압축 참조 테이블
2. **코드베이스 검사**: 구문적 검사(grep) + 의미적 검사(로직 버그)
3. **심화 검증**: 거짓 양성 필터링
4. **보고서 생성**: 심각도 + 코드 스니펫 + 수정 권장

각 참조 파일 포함: 전제 조건, 취약한 패턴, 탐지 휴리스틱, 거짓 양성, 해결책

### 12.5 도구 활용 전략 (CTF/감사)

```
감사 워크플로우:
1단계: 자동화 스캔
   ├── Slither (정적 분석)
   ├── Aderyn (정적 분석)
   ├── scv-scan (36 패턴 체크)
   └── Semgrep (커스텀 규칙)

2단계: AI 보조 분석
   ├── QuillShield BSA (행동 분석)
   ├── Trail of Bits variant-analysis (유사 취약점)
   ├── sc-auditor Map-Hunt-Attack
   └── Solodit 과거 발견 검색

3단계: 수동 검증
   ├── 불변식 식별 + Foundry 퍼징
   ├── 경제 모델 분석
   ├── 크로스 컨트랙트 상호작용
   └── PoC 작성

4단계: 검증
   ├── Foundry fork 테스트
   ├── Formal verification (KEVM / Certora)
   └── Property-based testing
```

---

## 13. 추천 학습 순서 및 주차별 계획

### 13.1 Phase 1-2: 기초 강화 (1-2주)

| 주차 | 월 | 화 | 수 | 목 | 금 |
|------|---|---|---|---|---|
| 1주 | EVM opcode (evm.codes) | Storage/Memory 모델 | delegatecall 심화 | CREATE2 메타모픽 | Transient Storage |
| 2주 | Solidity 컴파일러 행동 | ABI 인코딩 수동 | Vyper vs Solidity | 컴파일러 버그 분석 | Ethernaut 1-10 |

### 13.2 Phase 3: 취약점 패턴 (3-6주)

| 주차 | 주제 | evmresearch 노트 수 |
|------|------|-------------------|
| 3주 | Reentrancy 전 변형 + Access Control | 30개 |
| 4주 | Oracle/Flash Loan + 산술/정밀도 | 27개 |
| 5주 | Proxy/Upgrade + 서명/암호학 | 35개 |
| 6주 | ERC-20 비표준 + ERC-4337 + EIP-7702 | 36개 |

### 13.3 Phase 4-5: 익스플로잇 + 방어 (7-9주)

| 주차 | 주제 |
|------|------|
| 7주 | 실제 익스플로잇 분석 (Bybit, Euler, Penpie, Curve) + PoC 재현 |
| 8주 | 실제 익스플로잇 분석 (Ronin, Parity, dForce, Beanstalk) + PoC 재현 |
| 9주 | 방어 패턴 48개 + 보안 도구 실습 (Slither, Foundry fuzzing, scv-scan) |

### 13.4 Phase 6-7: DeFi + Consensus (10-12주)

| 주차 | 주제 |
|------|------|
| 10주 | DeFi 프로토콜 메커니즘 (AMM, Lending, Stablecoin) |
| 11주 | Consensus Layer 기초 (Casper FFG, LMD-GHOST, Slashing) |
| 12주 | Consensus Layer 심화 (MEV/PBS, P2P, 클라이언트 다양성) |

### 13.5 Phase 8: ZK/L2 (13-14주)

| 주차 | 주제 |
|------|------|
| 13주 | zkVM Soundness + L2 시퀀서/롤업 보안 |
| 14주 | DA Layer + 브릿지 보안 + ZK 증명 시스템 |

### 13.6 Phase 9-10: CTF (15-20주)

| 주차 | 주제 |
|------|------|
| 15주 | Damn Vulnerable DeFi 전체 풀이 |
| 16주 | Paradigm CTF / Blazctf 과거 문제 풀이 |
| 17주 | DeFiHackLabs 실제 해킹 재현 |
| 18주 | CTF 문제 설계 (Easy/Medium) |
| 19주 | CTF 문제 설계 (Hard/Expert) |
| 20주 | Consensus + ZK 문제 설계 + 테스트 |

---

## 14. 참고 자료 전체 링크

### 14.1 evmresearch.io 전체 통계

| 카테고리 | 페이지 수 | URL 패턴 |
|---------|----------|---------|
| **evm-internals** | 17 | `evmresearch.io/evm-internals/{title}` |
| **solidity-behaviors** | 10 | `evmresearch.io/solidity-behaviors/{title}` |
| **vulnerability-patterns** | 269 | `evmresearch.io/vulnerability-patterns/{title}` |
| **exploit-analyses** | 21 | `evmresearch.io/exploit-analyses/{title}` |
| **security-patterns** | 48 | `evmresearch.io/security-patterns/{title}` |
| **protocol-mechanics** | 19 | `evmresearch.io/protocol-mechanics/{title}` |
| **기타** | 3 | index, contributors, image |
| **총합** | **387** | |

### 14.2 추가 분석 자료

| 자료 | URL | 유형 |
|------|-----|------|
| OSecure zkVM 분석 | https://osec.io/blog/2026-03-03-zkvms-unfaithful-claims/ | 블로그/연구 |
| Pashov Skills | https://github.com/pashov/skills | Claude 스킬 |
| Trail of Bits Skills | https://github.com/trailofbits/skills | Claude 스킬 (35+) |
| Cyfrin Solskill | https://github.com/Cyfrin/solskill | Claude 스킬 |
| SCV Scan | https://github.com/kadenzipfel/scv-scan | Claude 스킬 |
| QuillShield Skills | https://github.com/quillai-network/qs_skills | Claude 스킬 (10) |
| SC Auditor | https://github.com/Archethect/sc-auditor | MCP 도구 |
| YieldBlox PoC | https://github.com/DK27ss/YieldBlox-10M-PoC | 익스플로잇 PoC |

### 14.3 핵심 외부 참고 자료

| 분류 | 자료 |
|------|------|
| **사양** | ethereum/consensus-specs, ethereum/execution-specs |
| **Wargame** | Ethernaut, Damn Vulnerable DeFi, EVM Puzzles, Curta |
| **CTF** | Paradigm CTF, Blazctf, Code4rena |
| **도구** | Foundry, Slither, Aderyn, Semgrep, Certora, KEVM |
| **연구** | Trail of Bits publications, OSecure blog, Halborn reports |
| **해킹 DB** | DeFiHackLabs, rekt.news, Solodit |

### 14.4 evmresearch.io 전체 노트 인덱스

<details>
<summary>evm-internals (17개) — 클릭하여 펼치기</summary>

1. CREATE2 enables metamorphic contract attacks by allowing a self-destructed contract to be redeployed with different bytecode at the same trusted address
2. EVM opcode incompatibility across chains causes failures when contracts assume uniform opcode support
3. EXTCODESIZE returns zero during constructor execution allowing contracts to bypass code-size-based EOA checks
4. custom storage layouts enable powerful proxy patterns but manual slot math errors can corrupt data
5. delegatecall executes code from another contract using the callers storage context
6. evm memory gas costs grow quadratically making large allocations prohibitively expensive
7. low-level calls to non-existent contracts succeed silently because the EVM treats empty addresses as successful
8. memory and calldata values are not packed unlike storage
9. memory-to-memory assignment in solidity creates references not copies enabling aliasing bugs when both variables modify the same data
10. solidity compiler packs multiple small values into one storage slot but writing requires reading the full slot
11. solidity delete on mappings contained within arrays leaves orphaned data in storage because mappings cannot track their keys
12. solidity pure functions use STATICCALL but cannot prevent state reads at the EVM level creating a false safety guarantee
13. storage variable ordering affects gas costs because suboptimal ordering wastes storage slots
14. transient storage introduces new storage semantics with novel security implications
15. writing contract logic in yul or assembly can bypass access control mechanisms only implemented in solidity
16. yul division by zero returns zero rather than reverting unlike solidity checked arithmetic

</details>

<details>
<summary>solidity-behaviors (10개) — 클릭하여 펼치기</summary>

1. Panic(uint256) error codes provide a formal taxonomy of compiler-inserted revert conditions in solidity 0.8
2. Solidity's error hierarchy treats panics as unexpected bugs rather than expected failure modes making contracts structurally unprepared to handle panic-triggering inputs
3. abi types are not self-describing so the decoder must know the interface to interpret values
4. gas optimization via unchecked blocks creates tension with arithmetic safety guarantees
5. private visibility in solidity only restricts contract-level access while all on-chain data remains publicly readable
6. selfdestruct was deprecated in solidity 0.8.18 via eip-6049
7. solidity 0.8.0 introduced default arithmetic overflow protection making unchecked blocks the new attack surface
8. solidity 0.8.31 deprecates send and transfer signaling the move away from fixed gas stipend patterns
9. solidity lacks floating-point types so all division rounds toward zero losing precision when numerator is smaller than denominator

</details>

<details>
<summary>exploit-analyses (21개) — 클릭하여 펼치기</summary>

1. DPRK-affiliated threat actors account for the majority of crypto theft losses by shifting from smart contract exploitation to social engineering infrastructure compromise and supply chain attacks
2. ERC-4337 malformed calldata in EntryPoint pack() functions allows post-signing mutation of UserOperation fields undermining paymaster sponsorship intent
3. Profanity vanity address generator used a 32-bit seed keyspace making all generated private keys recoverable from any observed transaction signature
4. bridge validator set compromise enables unauthorized message relay as demonstrated by the Ronin $625M exploit
5. cross-chain bridge cryptographic failures account for 40 percent of total Web3 hack losses through validator key compromise and signature scheme weaknesses
6. furucombo exploit demonstrated unrestricted delegatecall enabling storage approval manipulation
7. parity wallet hack demonstrated that selfdestruct in implementation contracts permanently bricks proxy systems
8. self-liquidation via flash loan is profitable when borrowed funds trigger and profit from the borrowers own liquidation before repaying the flash loan
9. social engineering and key management failures drove 65 percent of 2025 crypto losses and are outside the scope of any code-level security analysis
10. supply chain injection into hardware wallet signing interfaces enables theft without private key extraction by tricking operators into signing fraudulent transactions
11. the Bunni exploit demonstrated that individually safe rounding directions become unsafe under multi-operation composition
12. the Bybit exploit demonstrated that JavaScript injection into web-based signing infrastructure can bypass hardware wallet protection and drain cold wallet assets
13. the Euler Finance donateToReserves exploit demonstrated that economic logic flaws invisible to all automated tooling require protocol-specific manual review to detect
14. the Orbit Chain exploit demonstrated that insider threat via deliberate firewall policy degradation before departure creates bounded-time exploit windows in bridge infrastructure
15. the Penpie exploit demonstrated reentrancy in reward-harvesting via permissionless Pendle market creation enabling flash-loan-amplified extraction of $27 million
16. the Radiant Capital exploit demonstrated that malware intercepting Gnosis Safe signing requests bypasses 3-of-11 multisig by exploiting hardware wallet blind signing
17. the SushiSwap RouteProcessor2 exploit demonstrated that callback mechanisms on unvalidated user-supplied addresses grant attackers delegated execution context within the calling protocol
18. the USPD exploit demonstrated that publicly disclosed deployment vulnerabilities remain exploitable when teams apply published mitigations to new code without auditing their own deployment procedures
19. the WazirX exploit demonstrated that harvesting valid multisig signatures via a compromised custody UI enables malicious contract upgrades without any signer awareness
20. the yETH exploit demonstrated that stale cached state after pool drainage enables infinite token minting through bootstrap re-entry

</details>

<details>
<summary>security-patterns (48개) — 클릭하여 펼치기</summary>

1. 92% of smart contracts exploited in 2025 had passed security reviews indicating specification completeness rather than code correctness is the primary audit gap
2. CREATE2 deterministic deployment enables atomic initialization of circularly dependent proxy contracts
3. DeFi protocols on L2 must check L2 sequencer uptime before consuming Chainlink price feeds
4. EIP-6780 restricts SELFDESTRUCT to same-transaction contracts eliminating metamorphic contract patterns
5. EOA access control invariant is the single most effective runtime exploit guard blocking 18 of 27 distinct exploits
6. ERC-7265 on-chain circuit breakers are fundamentally reactive and cannot prevent the initial attack transaction
7. KEVM provides complete executable formal semantics of the EVM
8. RFC 6979 deterministic nonce generation eliminates ECDSA private key leakage from randomness failures
9. atomic proxy deployment by passing initialization data to the ERC1967Proxy constructor
10. audit coverage expires when protocol assumptions change after the audit
11. automated security tools combined catch approximately 60 percent of exploitable vulnerabilities
12. balance invariants requiring sum of user balances equals total supply
13. bug heuristic methodology combines code patterns easy to get wrong with pre-defined high-impact targets
14. calling a function X times with value Y should equal calling it once with value XY as a fuzzing invariant
15. circuit breakers provide independent security guarantees when implemented at a layer separate from application logic
16. combined runtime invariant guards block 85 percent of exploits with less than 1 percent gas overhead
17. combining multiple security analysis tools detects more unique vulnerabilities
18. complementary function pairs that don't mirror all state mutations may have an asymmetry bug
19. defense-in-depth combining pre-deployment and post-deployment security layers reduces breach probability by 87 percent
20. detecting EIP-7702 delegation via the 0xef0100 prefix check
21. developer subconscious assumptions about prior state create systematic input validation gaps
22. double hashing Merkle leaves prevents second-preimage attacks
23. eip-1967 reserved storage slots prevent proxy implementation address collisions
24. eip-7201 namespaced storage provides structured collision avoidance
25. emergency pause multisig threshold of 50 to 70 percent optimally balances security against response speed
26. formal verification and fuzzing find systematically different bug classes
27. formal verification completeness paradox — 92% post-audit exploit rate shows mathematical certainty of the wrong thing provides no safety guarantee
28. formal verification finds bugs that all three major fuzzers miss
29. formal verification proves code matches a specification but cannot prove the specification itself is complete
30. formally rare bugs requiring inputs with probability below 1 in 2^80 are unreachable by fuzzers
31. governance systems must verify proposal code integrity at execution time
32. handler functions in invariant fuzz tests must satisfy preconditions
33. invariant analysis as a systematic audit methodology
34. locking pragma versions prevents deployment with untested compiler versions
35. multiplication before division is required in Solidity to minimize precision loss
36. off-chain transaction monitoring detects holistic attack patterns
37. openzeppelin initializable with initializer modifier prevents re-initialization attacks
38. post-deployment verification by directly reading ERC1967 implementation storage slots
39. proof of possession prevents BLS rogue-key attacks only when the PoP hash function is domain-separated
40. rage quit mechanisms give token holders a credible exit threat
41. restricting delegatecall to pre-verified logic contracts
42. snapshot-based voting power measurement at proposal creation time prevents flash loan governance attacks
43. state transition invariants preventing invalid progression
44. testing smart contracts with specification languages different from the implementation language
45. timelocks on contract ownership transfers provide the detection window
46. vyper module composition uses explicit uses initializes and exports keywords
47. writing correct invariants constitutes 80 percent of verification work

</details>

<details>
<summary>protocol-mechanics (19개) — 클릭하여 펼치기</summary>

1. Chainlink Proof of Reserve oracle feeds provide on-chain verification
2. DA-saturation and prover killer attacks exploit mismatches between EVM gas costs and ZK proving costs
3. ERC-3643 T-REX permissioned token standard
4. ERC-4337 EntryPoint singleton concentrates unconditional trust
5. ERC-7540 asynchronous redemption vaults prevent bank-run failure modes
6. L2 upgrade authority creates a security council governance tradeoff
7. Lido's concentration at 29 percent of staked ETH approaches consensus attack threshold
8. RWA recovery agent functions with burn-and-remint capability
9. RWA tokenization introduces off-chain legal wrapper failure risk
10. Uniswap V4 hooks introduce arbitrary external code execution into pool swap paths
11. Uniswap v4 modifyLiquidity callerDelta bundles accrued fees with principal
12. bridge upgrade transactions are a distinct exploit vector
13. commit-reveal schemes prevent frontrunning
14. concentrated liquidity AMMs amplify impermanent loss
15. perpetual DEX oracle-based models expose liquidity providers to toxic flow
16. the stablecoin trilemma
17. tick boundary edge cases in concentrated liquidity AMMs
18. token-level transfer cooldowns break sandwich attack atomicity

</details>

<details>
<summary>vulnerability-patterns (269개) — 클릭하여 펼치기</summary>

전체 269개 노트 목록은 본문의 Phase 3 섹션에서 카테고리별로 정리되어 있습니다.
각 노트는 `https://evmresearch.io/vulnerability-patterns/{title}` 형태로 접근 가능합니다.

</details>

---

> **이 문서는 evmresearch.io의 387개 노트, osec.io zkVM 분석, 6개 보안 도구 리포지토리, YieldBlox PoC를 종합 분석하여 작성되었습니다.**
