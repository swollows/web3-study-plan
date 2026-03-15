# Phase 7: Consensus Layer 보안

> **학습 목표**: Ethereum 합의 레이어의 보안 모델을 깊이 이해하고, 실제 공격 벡터와 방어 기법을 습득한다.

---

## 목차

1. [Validator 보안](#1-validator-보안)
2. [Staking & Restaking 보안](#2-staking--restaking-보안)
3. [MEV & PBS](#3-mev--pbs)
4. [Finality & Fork Choice](#4-finality--fork-choice)
5. [P2P 네트워킹 보안](#5-p2p-네트워킹-보안)
6. [클라이언트 다양성](#6-클라이언트-다양성)
7. [CTF 문제 유형](#7-ctf-문제-유형)

---

## 1. Validator 보안

### 1.1 Validator의 역할과 책임

Ethereum Proof of Stake(PoS) 전환 이후, 네트워크 보안은 ETH를 스테이킹한 validator들에 의해 유지된다. 각 validator는 32 ETH를 예치하고, 블록 제안과 증명(attestation) 의무를 수행한다.

**핵심 역할:**
- **Proposer**: 각 슬롯(12초)마다 무작위로 선택되어 블록을 제안
- **Attester**: 매 에포크(32슬롯, 약 6.4분)마다 체인 헤드에 대한 증명 제출
- **Sync Committee**: 512개 validator가 무작위 선택되어 가벼운 클라이언트 동기화 지원

### 1.2 Slashing 조건 상세

Slashing은 validator가 악의적이거나 규칙을 위반하는 행동을 했을 때 스테이크의 일부를 강제로 삭감하는 패널티이다.

#### 1.2.1 이중 투표 (Double Voting / Equivocation)

**공격 시나리오:**
```
Slot N에서 Validator V가:
  - 블록 A를 제안하고 서명
  - 동시에 블록 B를 제안하고 서명
  → 두 서명 모두 BLS-12-381로 검증 가능
  → 누구든 두 서명을 증거로 제출 가능
```

**기술적 세부사항:**
```
ProposerSlashing 구조체:
  - signed_header_1: BeaconBlockHeader + BLS서명
  - signed_header_2: BeaconBlockHeader + BLS서명

유효성 조건:
  1. 두 헤더의 slot이 동일
  2. 두 헤더의 proposer_index가 동일
  3. 두 헤더의 내용이 다름
  4. 두 BLS 서명이 모두 유효
```

**공격자 관점:**
이중 투표 공격은 단독으로는 실질적인 이익이 없다. 그러나 fork choice 조작과 결합하면 일부 노드를 다른 체인으로 유도할 수 있다. 주로 실수(클라이언트 버그, 여러 기기에서 동시 실행)로 발생한다.

#### 1.2.2 서라운딩 투표 (Surrounding Vote)

Casper FFG의 안전성을 보장하는 핵심 규칙으로, attester가 자신의 이전 증명을 "둘러싸거나" 이전 증명에 "둘러싸이는" 투표를 제출하면 슬래싱된다.

**수학적 정의:**
```
Attestation은 (source_epoch, target_epoch) 쌍을 포함.

서라운딩 위반:
  증명 A: (s1, t1)
  증명 B: (s2, t2)

  A가 B를 surrounds:  s1 < s2 AND t2 < t1
  A가 B에 surrounded: s2 < s1 AND t1 < t2
```

**공격 벡터:**
```
정직한 validator가 네트워크 파티션 상황에서:
  - 파티션 전: (epoch 5, epoch 10)으로 투표
  - 파티션 후(다른 fork): (epoch 6, epoch 9)로 투표
  → epoch 6 > epoch 5, epoch 9 < epoch 10
  → 두 번째 투표가 첫 번째에 surrounded
  → Slashable!
```

이것이 "validator는 항상 하나의 기기에서만 실행해야 한다"는 규칙의 근거다.

#### 1.2.3 제안자 슬래싱 (Proposer Slashing)

동일한 슬롯에서 두 개의 다른 블록에 서명하면 발생. 위의 이중 투표와 동일 원리.

**실제 발생 사례:**
- 2023년 1월: Prysm 클라이언트 설정 오류로 여러 validator가 동시에 두 기기에서 실행
- 복구 불가 → 약 수백만 달러 상당 ETH 슬래싱

### 1.3 상관관계 페널티 (Correlation Penalty)

단순 슬래싱보다 훨씬 위험한 메커니즘. 동시에 슬래싱된 validator 수에 비례하여 추가 패널티를 부과한다.

**공식:**
```
penalty_factor = (3 × slashed_validators_in_window) / total_validators

최소 페널티: 1/32 (약 1 ETH)
최대 페널티: 전체 스테이크 (32 ETH)

slashing_window = 8192 에포크 (약 36일)
```

**시나리오 분석:**
```
총 validator: 500,000명 (16,000,000 ETH 스테이킹)
동시 슬래싱: 166,667명 (전체의 1/3)

penalty_factor = 3 × 166,667 / 500,000 = 1.0 (100%)
→ 각 validator 32 ETH 전액 슬래싱!
```

**왜 이 설계인가?**
- 소규모 실수(개인 실수): 최소 패널티
- 대규모 협력 공격(1/3 이상): 전액 슬래싱
- 공격 비용을 기하급수적으로 증가시켜 억지력 제공

### 1.4 BLS-12-381 키 관리

BLS(Boneh-Lynn-Shacham) 서명은 다수의 서명을 하나로 집계할 수 있어 Ethereum PoS의 핵심 기술이다.

#### 1.4.1 키 분리 아키텍처

**서명키 (Signing Key / Hot Key):**
```
- 목적: 블록 제안, 증명, sync committee 참여
- 특성: 온라인 상태 유지 필요 (슬롯마다 사용)
- 위험: 노출 시 슬래싱 가능 (두 기기에서 동시 사용)
- 저장: validator 클라이언트 메모리/keystore
- 파일: keystore-m_12381_3600_N_0_0-timestamp.json
```

**출금키 (Withdrawal Key / Cold Key):**
```
- 목적: 스테이크 출금 인증 (BLS 또는 ETH 주소)
- 특성: 오프라인 보관 가능 (드물게 사용)
- 위험: 노출 시 ETH 도난 가능 (슬래싱 없음)
- 저장: 하드웨어 지갑, 오프라인 저장소
- 형식: 0x01 접두사 + ETH 주소 (권장) 또는 BLS 공개키
```

#### 1.4.2 EIP-2335 Keystore 형식

```json
{
  "crypto": {
    "kdf": {
      "function": "scrypt",
      "params": {
        "dklen": 32,
        "n": 262144,
        "r": 8,
        "p": 1,
        "salt": "ab0c7876052600dd703518d83d..."
      }
    },
    "checksum": {
      "function": "sha256",
      "message": "149aafa27b041f3..."
    },
    "cipher": {
      "function": "aes-128-ctr",
      "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
      "message": "54ecc8863c0550351eee5720f3be6a5d..."
    }
  },
  "description": "",
  "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
  "path": "m/12381/3600/0/0/0",
  "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
  "version": 4
}
```

#### 1.4.3 BLS 취약점: 키 집계 공격

**Rogue Key Attack:**
```
정직한 validator A의 공개키: PK_A
공격자 B가 PK_B' = PK_B - PK_A 를 등록

집계 키: PK_A + PK_B' = PK_A + PK_B - PK_A = PK_B

→ 공격자가 집계 서명을 단독으로 위조 가능
```

**방어 (Proof of Possession):**
```
validator 등록 시 자신의 서명키로 자신의 공개키에 서명 제출
→ PK_B' = PK_B - PK_A 형태의 키는 PoP 검증 실패
→ Ethereum은 이를 deposit 시 강제
```

### 1.5 Validator Lifecycle

```
[입금] → [대기] → [활성화] → [운영] → [자발적 탈퇴] → [탈퇴 대기] → [출금 가능]
  ↓                                         ↓
32 ETH                                  슬래싱 탈퇴
deposit.sol                              (강제)
```

**각 단계 상세:**

**입금 단계:**
```solidity
// Deposit Contract (0x00000000219ab540356cBB839Cbe05303d7705Fa)
function deposit(
    bytes calldata pubkey,           // BLS 공개키 (48 bytes)
    bytes calldata withdrawal_credentials, // 출금 자격증명 (32 bytes)
    bytes calldata signature,        // BLS 서명 (96 bytes)
    bytes32 deposit_data_root        // SSZ 해시
) external payable;
// msg.value >= 1 ETH, 32 ETH 도달 시 validator 활성화 대기
```

**대기 큐:**
```
입장률 제한: churn_limit = max(4, total_validators / 65536)
현재(500k validator): churn_limit = max(4, 7) = 7 validator/에포크
대기 시간: 최대 수주 가능 (수요에 따라)
```

**활성화:**
```
조건: 입금 확인 + 큐 통과 + ETH 잔액 ≥ 32 ETH
상태: pending → active
```

**탈퇴 (Voluntary Exit):**
```
최소 활성화 기간: 256 에포크 (약 27시간)
탈퇴 큐: 입장과 동일한 churn_limit 적용
탈퇴 지연: MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256 에포크
```

**출금:**
```
부분 출금: 32 ETH 초과분 자동 스윕 (EIP-4895, Shanghai)
전체 출금: 탈퇴 완료 후 전액 출금
조건: withdrawal_credentials가 0x01 형식이어야 함
```

---

## 2. Staking & Restaking 보안

### 2.1 LST(Liquid Staking Token) 디페깅 위험

**stETH (Lido) 아키텍처:**
```
사용자 ETH → Lido → validator 운영 → stETH 발행
stETH는 ETH에 1:1로 페깅되도록 설계
리베이스(rebase): 매일 보상 반영, stETH 잔액 자동 증가
```

**디페깅 시나리오 1: 대규모 슬래싱**
```
시나리오: Lido의 여러 node operator가 동시에 슬래싱
영향: stETH 준비금 감소
반응: stETH/ETH 가격 하락
연쇄: stETH 담보 대출 포지션 청산 시작

예시 (가상):
  stETH 총 발행: 10,000,000 stETH
  슬래싱으로 500,000 ETH 손실
  stETH 실질가치: 0.95 ETH

  Curve stETH/ETH 풀: 유동성 제공자 패닉 이탈
  → stETH 가격: 0.95 → 0.90 → ...
  → Aave/Compound의 stETH 담보 청산 트리거
  → 더 많은 stETH 매도 → 가격 추가 하락
  → 연쇄 청산 (Cascade Liquidation)
```

**실제 사례 (2022년 6월 Terra 사태 여파):**
```
stETH 가격: 0.9414 ETH까지 하락
원인: 알고리즘 스테이블코인 붕괴로 전반적 디레버리징
Celsius가 stETH 대량 매도 → 유동성 위기
```

**디페깅 시나리오 2: 출금 지연**
```
The Merge 이전 (2022): stETH 출금 불가
→ ETH가 필요한 사용자는 시장에서 stETH를 ETH로 교환해야 함
→ 대량 매도 시 디스카운트 발생
→ 출금 가능해도 큐 대기 시 단기 유동성 위기 가능
```

### 2.2 EigenLayer Restaking 위험

**Restaking 개념:**
```
기존: ETH → 스테이킹 → Ethereum 보안 기여
Restaking: ETH → 스테이킹 → Ethereum 보안 기여 + AVS 보안 기여
         (동일 ETH로 여러 프로토콜 보안)
```

**복합 슬래싱 위험:**
```
Operator가 10개 AVS를 동시에 운영한다고 가정:
  - AVS1 슬래싱: 10% 손실
  - AVS2 슬래싱: 10% 손실 (독립적 발생)
  - ...
  - AVS10 슬래싱: 10% 손실

  총 손실 가능: 100% (전액!)

  단순 합산이 아닌 이유: 슬래싱은 남은 잔액에 적용
  1.0 × 0.9^10 = 0.349 (34.9% 남음)
  → 65.1% 손실
```

**AVS 슬래싱의 독특한 위험:**

```
문제: AVS의 슬래싱 조건이 명확하지 않을 수 있음

시나리오: Oracle AVS에서
  - 올바른 가격을 보고했지만
  - 보고 타이밍이 늦어 AVS 규칙 위반
  → 정직한 operator도 슬래싱!

EigenLayer의 접근:
  - Veto Committee: 부당한 슬래싱 거부권
  - 슬래싱 실행 전 72시간 지연
  - 그러나 신뢰 가정이 추가됨
```

**EigenLayer 공격 벡터:**
```
1. AVS 스마트 컨트랙트 취약점
   → 취약한 AVS에 opt-in한 모든 operator 슬래싱

2. 거버넌스 공격
   → AVS 파라미터 변경으로 부당한 슬래싱 조건 추가

3. Operator 집중도
   → 소수 operator가 다수 AVS 운영
   → 단일 실패 지점
```

### 2.3 Lido 집중도 위험

**현황 (2024년 기준):**
```
Lido ETH 스테이킹 점유율: ~29%
전체 validator의 ~29%가 Lido 프로토콜 하에 있음

위험 임계값: 33.3% (1/3)
→ 1/3 이상이면 finality를 방해 가능
→ 50% 이상이면 단독으로 체인 재조직 가능
```

**집중도 공격 시나리오:**
```
시나리오: Lido DAO가 악의적으로 행동하거나 해킹된 경우

1. Finality 방해 (33% 임계값 도달 시):
   - 전체 validator 투표의 1/3 이상 거부
   - 어떤 체크포인트도 정당화(justify) 불가
   - 체인 finality 정지
   - 경제적 패닉 유발

2. 검열 (34%+):
   - 특정 트랜잭션 포함 거부
   - 규제 기관 요청 준수 가능
   - 탈중앙화 훼손

3. 잠재적 51% 공격 (50%+):
   - Lido가 현재는 아니지만 성장 지속 시 위험
```

**방어 메커니즘:**
```
1. Inactivity Leak: 참여 안하는 validator 자동 ETH 감소
   → 악의적 validator 집합의 비중 자연 감소

2. 소셜 컨센서스: 커뮤니티 하드포크 결정 가능

3. Lido의 자체 제한:
   - DVT(Distributed Validator Technology) 도입
   - 다수의 독립 node operator 유지
   - 자체 시장점유율 제한 논의
```

---

## 3. MEV & PBS

### 3.1 MEV(Maximal Extractable Value) 개요

MEV는 블록 생산자(proposer)가 트랜잭션 순서, 포함/제외를 조작하여 추출할 수 있는 추가 가치다.

**MEV의 종류와 크기:**
```
Sandwich Attack: 사용자 DEX 거래 앞뒤에 자신의 거래 삽입
  - 연간 수억 달러 규모

Arbitrage: DEX 간 가격 차이 이용
  - 가장 일반적, 시장 효율화에 기여

Liquidation: 담보 청산 트리거
  - 연간 수억 달러

JIT(Just-In-Time) Liquidity: 대형 스왑 직전 유동성 추가
  - LP 수익을 front-runner가 탈취

Time-Bandit Attack: 과거 블록 재조직
  - MEV가 충분히 크면 이전 블록 재작성 시도
```

### 3.2 Sandwich Attack 상세

```
공격 전 상황:
  Uniswap USDC/ETH 풀
  ETH 가격: $2000
  사용자 A: 100 USDC → ETH 스왑 (mempool에 있음)

공격자 순서:
  1. Front-run: 공격자가 먼저 100 USDC → ETH 스왑
     → ETH 가격 $2010으로 상승 (슬리피지)
  2. Victim tx: 사용자 A의 스왑 실행
     → 더 비싼 가격($2010)에 ETH 구매
  3. Back-run: 공격자가 ETH → USDC 스왑
     → $2010에 산 ETH를 더 높은 가격에 팔아 차익 실현

결과:
  사용자 A: 예상보다 적은 ETH 수령 (slippage tolerance 소진)
  공격자: 무위험 차익 획득
```

**Sandwich 방어:**
```solidity
// 낮은 slippage tolerance 설정
amountOutMin = expectedAmount * 99 / 100; // 1% 허용

// Private mempool 사용 (Flashbots Protect)
// 또는 배치 경매 DEX (CoW Protocol)
```

### 3.3 Proposer-Builder Separation (PBS)

**문제 배경:**
```
Naïve PoS: proposer가 직접 블록 내용 구성
→ MEV를 직접 추출하려면 정교한 인프라 필요
→ 전문 MEV 추출 능력 없는 소규모 validator 불이익
→ 중앙화 압력
```

**PBS 구조:**
```
Builder (블록 빌더):
  - 전 세계 mempool 모니터링
  - 정교한 MEV 추출 및 순서 최적화
  - 최대 가치의 블록 구성
  - Proposer에게 bid 제출 (block + 보상 약속)

Proposer (Validator):
  - 여러 builder의 bid 중 최고가 선택
  - 블록 내용을 직접 보지 않고 커밋(blind signing)
  - 보상 수령

Relay:
  - Builder와 Proposer 사이의 신뢰 중개자
  - Builder 블록의 유효성 검증
  - Proposer에게 block header만 노출 (내용 비공개)
  - Proposer가 서명하면 전체 블록 공개
```

**MEV-Boost 구현:**
```
현재 Ethereum의 PBS는 out-of-protocol (MEV-Boost)
약 90%+ validator가 MEV-Boost 사용

위험:
1. Relay 중앙화: Flashbots, BloXroute 등 소수 relay
2. Relay 검열: OFAC 준수 요구로 특정 주소 트랜잭션 제외
3. Relay 단일 실패점: relay 다운 시 해당 validator 수익 감소
```

**enshrined PBS (ePBS):**
```
현재 논의 중인 프로토콜 내 PBS
- 별도 relay 없이 프로토콜 레벨에서 처리
- Inclusion List: proposer가 포함할 트랜잭션 지정 (검열 저항)
- Attester-Proposer Separation: 추가 분리
```

### 3.4 검열 저항성 (OFAC 이슈)

```
2022년 8월 미국 재무부 Tornado Cash 제재:
  - Flashbots가 OFAC 준수 결정
  - 제재된 주소의 트랜잭션 포함 거부

영향 (2022년 10월 피크):
  - 약 73%의 블록이 OFAC 준수 relay를 통해 생성
  - 제재 주소 트랜잭션: 수십 블록 지연

해결책:
1. 비-OFAC relay 사용 (Agnostic Relay 등)
2. Inclusion List (현재 개발 중)
3. 다수 relay 연결로 분산
```

### 3.5 JIT(Just-In-Time) Liquidity 공격

```
공격 과정:
  1. 대형 스왑 트랜잭션 감지 (예: 1M USDC → ETH)
  2. 스왑 직전에 해당 가격 범위에 유동성 집중 추가
  3. 스왑 실행 (JIT가 제공한 유동성으로 낮은 슬리피지)
  4. 스왑 직후 유동성 제거
  5. 수수료 수익 획득

영향:
  일반 LP: 실질적으로 수수료 수익을 JIT에게 빼앗김
  스왑 사용자: 가격 관점에서는 이점 (낮은 슬리피지)
```

### 3.6 Time-Bandit Attack

```
조건: 미래 N블록의 MEV > 현재 블록 보상 + 재조직 비용

시나리오:
  - 블록 1000에 1M ETH MEV 기회 존재 (가상)
  - 공격자가 블록 1000을 재작성하여 MEV 추출
  - 블록 1001~1005를 fork하여 자신의 체인에서 계속

방어:
  - Casper FFG finality: 2 에포크(약 12분) 후 재조직 불가
  - 현재: finalized 블록은 time-bandit 불가
  - 취약점: finalize 전 블록들 (최대 약 12분)
```

---

## 4. Finality & Fork Choice

### 4.1 Casper FFG (Friendly Finality Gadget)

**기본 원리:**
```
Casper FFG는 블록체인에 경제적 확정성을 부여하는 메커니즘

핵심 개념:
  Checkpoint: 에포크의 첫 번째 블록
  Justified: 2/3 이상의 validator가 해당 checkpoint를 지지
  Finalized: Justified된 checkpoint의 직접 자식도 Justified
```

**Justification 과정:**
```
에포크 E 종료 시:
  1. 모든 attester가 (source, target) 쌍으로 투표
     source: 마지막으로 justified된 checkpoint
     target: 현재 에포크의 checkpoint

  2. 투표 집계:
     if (총 투표 스테이크 / 전체 활성 스테이크) ≥ 2/3:
       target checkpoint가 JUSTIFIED

  3. 연속 두 에포크가 모두 justified되면:
     이전 epoch의 checkpoint가 FINALIZED
```

**수식:**
```
Justification:
  votes(checkpoint) ≥ (2/3) × total_active_balance

Finalization:
  if justified(N) AND justified(N+1):
    finalized(N) = true

단, N+1의 source = N (직접 연결)
```

**안전성 증명 (E1, E2 정리):**
```
Casper의 두 가지 보장:

E1 (Accountable Safety):
  두 conflicting finalized checkpoint가 존재하면
  → 전체 validator의 1/3 이상이 slashable 행동 수행
  → 슬래싱으로 최소 (1/3 × total_stake) 손실 보장

E2 (Plausible Liveness):
  슬래싱이 없는 상황에서
  → 충분한 온라인 validator만 있으면 항상 새 checkpoint 정당화 가능
```

### 4.2 LMD-GHOST Fork Choice

**GHOST (Greedy Heaviest Observed SubTree):**
```
기존 longest chain rule의 문제:
  Uncle 블록들의 작업이 무시됨
  → 대형 마이너 유리 (작은 블록 시간으로 uncle 최소화)

GHOST:
  각 분기점에서 "가장 무거운" (더 많은 지지를 받은) 방향 선택
  단순히 길이가 아닌 누적 difficulty/weight 고려
```

**LMD (Latest Message Driven):**
```
PoS에서 각 validator의 가장 최신 메시지만 카운트
(오래된 메시지는 무시)

이유: 구 메시지가 여전히 유효하면 validator가
      새 fork를 지지해도 구 fork에도 영향 주는 문제 방지
```

**LMD-GHOST 알고리즘:**
```python
def find_head(store, justified_checkpoint):
    head = justified_checkpoint.root

    while True:
        children = get_children(store, head)
        if not children:
            return head

        # 각 자식의 최신 메시지 기반 weight 계산
        def weight(child):
            return sum(
                validator_balance(v)
                for v in get_latest_attesting_validators(store, child)
            )

        # 가장 무거운 자식 선택 (동점 시 해시값으로 tie-break)
        head = max(children, key=lambda c: (weight(c), c))
```

### 4.3 Balancing Attack

**발견자:** Neuder et al. (2020), "Balancing Attack"

**공격 원리:**
```
공격자 목표: LMD-GHOST의 fork choice를 불안정하게 만들어
            일부 honest validator가 서로 다른 fork를 지지하게 만듦

준비물:
  - 약 33%의 validator 통제 (attacker)
  - 네트워크 타이밍 조작 능력 (지연 주입)

공격 과정:
  1. 두 개의 경쟁 블록 A, B 생성 (또는 자연 발생 대기)
  2. Honest validator의 절반에게 A에 대한 attestation을 보임
  3. 나머지 절반에게 B에 대한 attestation을 보임
  4. 공격자 attestation을 전략적으로 지연/조기 공개
  → 매 슬롯마다 oscillating fork 유지
```

**결과:**
```
- 최종성 지연 (Liveness 훼손)
- 33%의 공격자로 honest majority chain보다 자신의 체인을 우세하게 유지
- 현재는 View-Merge와 같은 대응책 논의 중
```

### 4.4 Long-Range Attack

**공격 개요:**
```
PoW와 달리 PoS에서는 "과거" 키가 의미를 잃지 않음

시나리오:
  1. 오래 전에 validator였던 A가 출금 후 private key 유지
  2. A의 private key로 genesis부터 다른 역사 작성
  3. 현재 chain과 경쟁하는 fork 생성

PoW에서는 불가: 과거 해시파워 재현 불가
PoS에서는 가능: 과거 서명키가 여전히 유효
```

**방어 메커니즘:**
```
1. Weak Subjectivity (Ethereum 채택):
   - 신규 노드는 최근 "신뢰할 수 있는 체크포인트"에서 동기화
   - 수개월 이전 분기는 유효한 fork로 인정 안 함

2. Key Evolving Signatures:
   - 주기적으로 새 키로 교체, 구 키 폐기
   - Ethereum은 현재 미채택

3. Finality:
   - 2 에포크 후 Finalized된 블록은 재조직 불가
   - Long-range는 finalized 지점 이후 적용 불가
```

**Weak Subjectivity 상세:**
```
Weak Subjectivity Period:
  현재 약 2주 ~ 수개월 (파라미터에 따라 다름)
  이 기간 내 genesis부터 재동기화는 안전

실제 적용:
  - 장기간 오프라인 노드는 커뮤니티에서 신뢰할 체크포인트 확인 필요
  - 교환소, 블록 탐색기 등에서 공식 체크포인트 제공
```

### 4.5 최종성 지연 및 인액티비티 리크

**시나리오: 대규모 validator 오프라인**
```
상황: 총 validator의 35%가 갑자기 오프라인

결과:
  - 온라인: 65% (2/3 미만)
  - Justification 불가 → Finality 정지

인액티비티 리크 시작 (4 에포크 후):
  - 오프라인 validator의 ETH 점진적 감소
  - 온라인 validator의 상대적 비중 증가

목표: 2/3 임계값 회복
  오프라인 validator가 충분히 감소하면
  온라인 65%가 2/3 이상 비중 차지
  → Finality 재개
```

**수식:**
```
인액티비티 페널티 (슬롯당):
  base_penalty = (validator_balance × INACTIVITY_PENALTY_QUOTIENT)
                 / EPOCHS_PER_YEAR

INACTIVITY_PENALTY_QUOTIENT = 2^24 (약 1670만)
→ 약 18일 후 validator 잔액의 약 1% 감소
→ 약 36일 후 약 2% 감소
```

---

## 5. P2P 네트워킹 보안

### 5.1 Ethereum P2P 스택

```
레이어:
  Discovery (discv5): 노드 탐색 (UDP 기반 Kademlia)
  Transport (libp2p): TCP/QUIC 연결 관리
  Application: Gossipsub (블록/증명 전파), Req/Resp (동기화)
```

### 5.2 Eclipse Attack

**개념:**
```
대상 노드의 모든 P2P 연결을 공격자 노드로 채워
외부 정보를 차단하는 공격
```

**공격 과정:**
```
1. Kademlia DHT 구조 분석:
   - 대상 노드 ID 근처에 다수의 공격자 노드 ID 생성
   - (discv5는 ID 기반 라우팅)

2. 연결 테이블 오염:
   - 공격자 노드들이 대상에게 지속 연결 시도
   - 대상의 peer table을 공격자 노드로 가득 채움

3. 격리 완료:
   - 대상 노드가 보는 모든 블록/증명이 공격자 제공
   - 실제 네트워크와 격리
```

**합의에 미치는 영향:**
```
1. Fork 조작: 공격자가 다른 fork를 보여줌
   → 대상 validator가 잘못된 chain에 attestation
   → 공격자 fork 지지 증가

2. MEV 공격 보조:
   → 대상 validator의 블록 제안 타이밍 조작
   → 공격자가 유리한 순간에 제안 허용

3. 슬래싱 유도:
   → 동일 슬롯에 두 개의 다른 view 제공
   → 대상이 두 블록에 모두 서명하게 유도
```

**방어:**
```
1. 다양한 소스에서 peer 연결 (고정 소수 peer 사용)
2. 신뢰할 수 있는 node 직접 연결 (static peers)
3. discv5의 identity verification 강화
4. 연결 시도 제한 (rate limiting)
```

### 5.3 Gossip 프로토콜 공격

**Gossipsub 구조:**
```
Ethereum beacon chain은 Gossipsub v1.1 사용
각 topic (unaggregated attestation, aggregate, blocks 등)
각 노드는 D=8 정도의 mesh peer 유지
```

**Gossip Spam 공격:**
```
공격: 무효한 메시지 대량 전파

1. 메시지 검증 전 전파:
   gossipsub은 기본적으로 받은 메시지를 검증 전 일부 전달
   → 공격자가 대량 무효 메시지 → 네트워크 부하

2. 유효하지만 쓸모없는 메시지:
   구 epoch의 attestation 전파
   → 검증은 통과하지만 무의미

3. 방어 (IHAVE/IWANT 메커니즘):
   - 메시지 ID 기반 중복 필터링
   - 악성 peer의 score 감소
   - 일정 이하 score의 peer 연결 해제
```

**NoDE DoS:**
```
공격 대상: beacon node의 RPC 또는 P2P 레이어

1. 대용량 블록 요청:
   sync 과정에서 수천 개의 블록 동시 요청
   → CPU/메모리 과부하

2. 잘못된 형식의 패킷:
   디코딩/검증에 많은 비용 소비

방어:
   - 요청 rate limiting
   - 최대 청크 크기 제한 (MAX_REQUEST_BLOCKS = 1024)
   - 응답 타임아웃
```

### 5.4 네트워크 파티션 공격

```
시나리오: 인터넷 인프라 수준 공격 (BGP hijacking 등)

영향:
  - 두 지역 validator 집단이 서로 다른 view 보유
  - 양쪽 모두 honest하지만 서로 다른 체인에 attestation
  - Finality 불가 (각 파티션의 2/3 불가)
  - 파티션 해제 후: 큰 재조직 발생 가능

실제 사례:
  - 2023년 5월: Ethereum beacon chain 분리 (클라이언트 버그)
  - 약 3 에포크 동안 finality 정지
```

---

## 6. 클라이언트 다양성

### 6.1 현재 클라이언트 생태계

**실행 레이어(Execution Layer) 클라이언트:**
```
Geth:        Go 구현, 점유율 ~60% (과거 ~80%)
Nethermind:  C# 구현, ~20%
Besu:        Java 구현 (Hyperledger), ~8%
Erigon:      Go 구현 (Geth fork, 더 효율적), ~10%
Reth:        Rust 구현 (신규, 고성능), 증가 중
```

**합의 레이어(Consensus Layer) 클라이언트:**
```
Prysm:       Go 구현, ~35%
Lighthouse:  Rust 구현, ~35%
Teku:        Java 구현 (Consensys), ~15%
Nimbus:      Nim 구현, ~8%
Lodestar:    TypeScript 구현, ~3%
Grandine:    Rust 구현, 소수
```

### 6.2 Supermajority 클라이언트 버그의 재앙적 결과

**이론적 시나리오:**
```
가정: Prysm이 65%의 validator에서 사용
상황: Prysm에 치명적 버그 발생

버그 유형 A: 잘못된 상태 전환 수용
  - Prysm validator 65%가 무효 블록을 유효로 처리
  - 65%가 동일한 잘못된 상태에서 계속 빌딩
  - 나머지 35%는 다른 체인 팔로우
  - 결과: 체인 분리 (65% 체인 vs 35% 체인)
  - 65% 체인은 "잘못된" 상태이지만 finalize될 수 있음!

  Correlation Penalty 발동:
  - 35% validator들이 소수 fork에 있음
  - finality에 필요한 2/3 없음
  - 모두 inactivity leak으로 패널티

버그 유형 B: 버그 조건에서 크래시
  - Prysm validator 65%가 갑자기 오프라인
  - 즉시 finality 정지 (35%만 온라인, 2/3 미만)
  - Inactivity leak 시작
```

**실제 사례 (2023년 5월 Prysm 버그):**
```
사건: Prysm v4.0.5 릴리스에 버그
증상: 특정 조건에서 Prysm 노드가 잘못된 state root 계산
결과: 약 3 에포크 동안 finality 정지
      ~200,000 validator가 inactivity leak 패널티
복구: 빠른 핫픽스 배포

교훈:
  1. 단일 클라이언트 의존은 전체 네트워크 위험
  2. 클라이언트 버그는 예상치 못한 방식으로 발현
  3. 다양성 > 단일 최적 클라이언트
```

### 6.3 클라이언트 다양성 확보 전략

**Solo Staker 가이드:**
```
추천 조합:
  - 실행: Geth 사용 중이라면 Nethermind/Reth로 전환 고려
  - 합의: Prysm 사용 중이라면 Lighthouse/Teku로 전환 고려
  - 목표: 어떤 클라이언트도 >33% 초과 금지
```

**node operator를 위한 다중 클라이언트 설정:**
```
Distributed Validator Technology (DVT):
  - SSV Network, Obol Network
  - 하나의 validator key를 N개로 분산 (threshold signature)
  - M-of-N 클라이언트가 합의해야 서명 가능

예: 4개 클라이언트 중 3개 동의 필요
  - 하나의 클라이언트 버그: 나머지 3개로 정상 운영
  - 클라이언트 다양성 자동 확보
```

---

## 7. CTF 문제 유형

### 7.1 BLS 서명 공격 유형

**문제 유형 1: 약한 메시지 바인딩**
```
시나리오: 특정 구현에서 BLS 서명이 충분한 컨텍스트를 바인딩하지 않음

취약 코드:
  msg = keccak256(abi.encode(amount))  // 컨텍스트 없음
  signature = bls_sign(private_key, msg)

공격:
  다른 컨텍스트(다른 체인, 다른 컨트랙트)에서 동일 서명 재사용

방어 코드:
  msg = keccak256(abi.encode(chain_id, contract_addr, nonce, amount))
```

**문제 유형 2: 집계 서명 검증 누락**
```
취약 코드:
  function verify(bytes[] pubkeys, bytes aggSig, bytes msg) {
      bytes aggKey = aggregate(pubkeys);
      return bls_verify(aggKey, aggSig, msg);  // PoP 검증 없음!
  }

공격 (Rogue Key):
  pubkey_malicious = legit_pubkey_2 - legit_pubkey_1
  aggregate = legit_pubkey_1 + (legit_pubkey_2 - legit_pubkey_1) = legit_pubkey_2
  공격자 혼자 legit_pubkey_2에 해당하는 서명 생성 가능
```

### 7.2 Fork Choice 조작

**CTF 시나리오:**
```
목표: 다른 참가자보다 더 빨리 최장 체인을 만들어
      double-spend 성공시키기

취약점 탐색:
  1. 테스트 체인의 total validator 수
  2. 내가 가진 validator 비율
  3. 상관관계 패널티 임계값

풀이 전략:
  1. 33% 이상 validator 확보
  2. 두 개의 competing fork 유지
  3. 다른 참가자 validator를 양쪽으로 분산시킴
  4. 자신의 fork를 전략적 시점에 강화
```

### 7.3 MEV 추출 CTF

**샌드위치 공격 구현:**
```python
import web3

def find_sandwich_opportunity(pending_tx):
    """
    멤풀의 대형 스왑을 감지하고 샌드위치 기회 탐색
    """
    # 트랜잭션 디코딩
    decoded = router.decode_function_input(pending_tx.input)
    if decoded[0].fn_name != 'swapExactTokensForTokens':
        return None

    amount_in = decoded[1]['amountIn']
    path = decoded[1]['path']

    # 슬리피지 계산
    amount_out_min = decoded[1]['amountOutMin']
    expected_out = get_expected_output(amount_in, path)
    allowed_slippage = (expected_out - amount_out_min) / expected_out

    if allowed_slippage > 0.005:  # 0.5% 이상 슬리피지 허용
        return {
            'target_tx': pending_tx,
            'front_run_amount': calculate_optimal_front_run(amount_in, allowed_slippage),
        }

def execute_sandwich(opportunity):
    # Front-run
    front_tx = build_swap_tx(
        amount_in=opportunity['front_run_amount'],
        path=opportunity['path'],
        gas_price=opportunity['target_tx'].gasPrice + 1  # 앞에 배치
    )

    # Bundle: [front_run, victim, back_run] 함께 flashbots에 제출
    bundle = [front_tx, opportunity['target_tx'], back_run_tx]
    flashbots.send_bundle(bundle, target_block=current_block + 1)
```

### 7.4 Consensus Split 시뮬레이션

**로컬 Ethereum 테스트넷 설정 (Kurtosis):**
```bash
# Kurtosis로 로컬 Ethereum 네트워크 구성
kurtosis run github.com/ethpandaops/ethereum-package \
  --args-file network_config.yaml

# network_config.yaml 예시
participants:
  - el_client_type: geth
    cl_client_type: lighthouse
    count: 4
  - el_client_type: nethermind
    cl_client_type: prysm
    count: 4

# 네트워크 파티션 시뮬레이션
# tc (traffic control)로 특정 노드 격리
sudo tc qdisc add dev eth0 root netem loss 100%

# 격리 후 두 파티션의 head 비교
for node in partition_a_nodes:
    head_a = eth_call(node, "eth_getBlockByNumber", ["latest"])

for node in partition_b_nodes:
    head_b = eth_call(node, "eth_getBlockByNumber", ["latest"])

print(f"Partition A head: {head_a['hash']}")
print(f"Partition B head: {head_b['hash']}")
# 다른 해시 → 체인 분리 확인
```

---

## 부록: 핵심 파라미터 참조

```
SLOTS_PER_EPOCH = 32
SECONDS_PER_SLOT = 12
EPOCHS_PER_ETH1_VOTING_PERIOD = 64
MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256 에포크
SHARD_COMMITTEE_PERIOD = 256 에포크
MIN_ATTESTATION_INCLUSION_DELAY = 1 슬롯
SLOTS_PER_HISTORICAL_ROOT = 8192
MIN_EPOCHS_TO_INACTIVITY_PENALTY = 4
INACTIVITY_PENALTY_QUOTIENT = 2^24
MIN_SLASHING_PENALTY_QUOTIENT = 128
PROPORTIONAL_SLASHING_MULTIPLIER = 1
MAX_EFFECTIVE_BALANCE = 32 ETH
EFFECTIVE_BALANCE_INCREMENT = 1 ETH
BASE_REWARD_FACTOR = 64
WHISTLEBLOWER_REWARD_QUOTIENT = 512
PROPOSER_REWARD_QUOTIENT = 8
MAX_VALIDATORS_PER_COMMITTEE = 2048
TARGET_COMMITTEE_SIZE = 128
```

---

## 참고 자료

- [Ethereum Proof-of-Stake Spec](https://github.com/ethereum/consensus-specs)
- [Casper the Friendly Finality Gadget (Buterin & Griffith)](https://arxiv.org/abs/1710.09437)
- [EigenLayer Whitepaper](https://docs.eigenlayer.xyz/overview/whitepaper)
- [MEV-Boost Architecture](https://boost.flashbots.net/)
- [Balancing Attack Paper (Neuder et al.)](https://arxiv.org/abs/2009.04987)
- [Client Diversity on Ethereum](https://clientdiversity.org/)
- [Weak Subjectivity (Buterin)](https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/weak-subjectivity/)
- [BLS Signature Spec (IETF)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature)
