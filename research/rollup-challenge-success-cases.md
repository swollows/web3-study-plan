# Rollup Challenge 성공 사례 조사 보고서

> **작성일**: 2026-03-15
> **목적**: 오늘 강의 자료 준비 — Optimistic Rollup 중심 서비스에서의 Challenge 성공 사례 분석
> **범위**: 2021년 Arbitrum 메인넷 론칭 이후 ~ 2026년 3월 15일까지 확인된 모든 사례

---

## 1. 개요: Optimistic Rollup Challenge 메커니즘

### 1.1 Challenge란?

Optimistic Rollup은 L2의 상태 전이(state transition)가 올바르다고 **낙관적으로 가정**하고, 일정 기간(challenge period, 통상 7일) 동안 누구든 잘못된 상태 루트(state root)에 대해 **이의를 제기(challenge)** 할 수 있는 메커니즘을 제공한다.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Sequencer  │────▶│  State Root  │────▶│   L1에 게시   │
│  (L2 블록 생성) │     │   (Output)   │     │  (Proposer)  │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                          ┌───────▼───────┐
                                          │ Challenge Period│
                                          │   (7일 대기)    │
                                          └───────┬───────┘
                                                  │
                                    ┌─────────────┴─────────────┐
                                    │                           │
                              이의 없음                    Challenge 발생
                                    │                           │
                              ┌─────▼─────┐            ┌───────▼───────┐
                              │  확정(Finalize)│         │  Dispute Game  │
                              └───────────┘            │  (분쟁 해결)    │
                                                       └───────┬───────┘
                                                               │
                                                 ┌─────────────┴─────────────┐
                                                 │                           │
                                           Defender 승리              Challenger 승리
                                           (원래 상태 유지)            (상태 루트 삭제/교체)
```

### 1.2 Challenge의 핵심 구성요소

| 구성요소 | 설명 |
|---------|------|
| **Proposer** | L2 상태 루트를 L1에 게시하는 주체 |
| **Challenger** | 잘못된 상태 루트에 이의를 제기하는 주체 |
| **Dispute Game** | Challenge를 해결하는 온체인 프로토콜 |
| **Bisection** | 분쟁 범위를 반복적으로 반으로 나누어 단일 명령어 수준까지 좁히는 과정 |
| **One-Step Proof** | 단일 명령어의 실행 결과를 온체인에서 검증하는 최종 단계 |
| **Challenge Period** | 이의 제기가 가능한 기간 (통상 7일) |
| **Bond** | Challenge 참여 시 예치해야 하는 담보금 |

---

## 2. 주요 Rollup별 Challenge 시스템 현황

### 2.1 Optimism (OP Stack)

| 항목 | 상세 |
|------|------|
| **프로토콜** | Fault Proof System (FPS) / Fault Dispute Game |
| **VM** | Cannon (MIPS 에뮬레이터) |
| **Challenge Period** | 7일 (최소 3.5일에 해결 가능) |
| **권한 구조** | Permissionless (2024년 6월 활성화) |
| **L2Beat Stage** | Stage 1 |
| **보호 자산** | ~$10B+ |

**타임라인:**
- **2024년 6월 10일**: 퍼미션리스 Fault Proof 메인넷 활성화 → Stage 1 달성
- **2024년 8월**: Spearbit, Cantina, Code4rena 보안 감사에서 고위험 취약점 2건 발견
- **2024년 8월**: 퍼미션리스 Fault Proof 일시 비활성화 (permissioned fallback 활성화)
- **2024년 9월 11일**: Granite 하드포크로 취약점 패치 후 퍼미션리스 재활성화
- **2025년~**: Base, Metal, Mode, Zora 등 OP Stack 체인으로 확대 적용

**특이사항:**
- Fault Proof 비활성화 기간 동안 Guardian 역할이 시스템을 보호
- DelayedWETH 컨트랙트가 본드 지급에 추가 지연을 적용하여 잘못된 게임 해결에 대한 안전장치 제공
- 최대 출금 지연: 7 + 3.5 + 9 = 19.5일

### 2.2 Arbitrum (BoLD)

| 항목 | 상세 |
|------|------|
| **프로토콜** | BoLD (Bounded Liquidity Delay) |
| **VM** | WAVM (WebAssembly) |
| **Challenge Period** | 6.4일 (분쟁 해결 포함 최대 ~13일 + 2일 유예) |
| **권한 구조** | Permissionless (2025년 2월 활성화) |
| **L2Beat Stage** | Stage 1 |
| **보호 자산** | ~$10B+ |
| **Challenge Bond** | Arbitrum One 기준 1,110 ETH |

**타임라인:**
- **2021년 5월**: Arbitrum One 메인넷 론칭 (허가형 밸리데이터만 가능)
- **2023년**: Interactive fraud proof 시스템 운영 (허가형)
- **2025년 2월**: BoLD 프로토콜 메인넷 배포 → 퍼미션리스 검증 활성화
- Arbitrum One 및 Nova 체인에서 운영 중

**BoLD 핵심 특징:**
- 시간 제한 분쟁 해결: 지연 공격(delay attack) 방지
- All-vs-All 방식: 기존 1:1 분쟁이 아닌 다자간 분쟁 가능
- 정직한 주장은 6.4일 후 확정 보장
- Security Council 2일 유예 기간

### 2.3 Kroma

| 항목 | 상세 |
|------|------|
| **프로토콜** | ZK Fault Proof (OP Stack 기반 + ZK 증명) |
| **증명 방식** | ZK 기반 fault proof (하이브리드) |
| **Challenge Period** | 7일 |
| **권한 구조** | Permissionless |
| **개발사** | Lightscale (위메이드 자회사) |

### 2.4 기타 Rollup

| Rollup | 기반 | Challenge 시스템 상태 | 비고 |
|--------|------|---------------------|------|
| **Base** | OP Stack | Fault Proof 활성화 (2025년 6월~) | OP Stack 공유 |
| **Blast** | OP Stack | Stage 0 (제한적) | 중앙화된 프로포저 |
| **Mantle** | OP Stack (수정) | Stage 0 | 자체 DA 레이어 |
| **Mode** | OP Stack | Fault Proof 예정 | OP Stack 업그레이드 따름 |
| **Zora** | OP Stack | Fault Proof 예정 | OP Stack 업그레이드 따름 |
| **Metis** | 자체 | 제한적 | 탈중앙 시퀀서 도입 |
| **Boba** | OP Stack (초기) | Stage 0 | 제한적 challenge |
| **Cartesi** | 자체 | Stage 2 달성 (2025년) | 퍼미션리스 fraud proof |

---

## 3. 확인된 Challenge 성공 사례

### 3.1 Kroma — 이더리움 롤업 역사상 최초의 메인넷 Challenge 성공 (2024년 4월 1일)

> **역사적 의의**: 2021년 5월 최초의 Optimistic Rollup(Arbitrum) 메인넷 론칭 이후 약 3년 만에 발생한 **최초의 실제 메인넷 Challenge 성공 사례**

#### 사건 개요

| 항목 | 상세 |
|------|------|
| **날짜** | 2024년 4월 1일 |
| **체인** | Kroma (OP Stack 기반 L2) |
| **원인** | Kroma 시퀀서의 L1 origin 문제 → 잘못된 블록 생성 |
| **결과** | 잘못된 Output Root 삭제 (체인 롤백 없음) |
| **참여 Challenger** | 12명 |
| **성공 Challenger** | 1명 (proveFault 함수 호출) |

#### 상세 분석

**1단계 — 시퀀서 오류 발생:**
Kroma 시퀀서가 참조하는 L1 origin에 문제가 발생하여, 시퀀서가 잘못된 L2 블록을 생성했다.

**2단계 — 잘못된 Output Root 제출:**
이 잘못된 블록을 기반으로 밸리데이터가 잘못된 output root를 L1에 제출했다.

**3단계 — Challenge 발생:**
Output root 제출 직후, **총 12명의 challenger**가 해당 output에 대해 이의를 제기했다.

**4단계 — Challenge 성공:**
12명의 challenger 중 **1명이 `proveFault` 함수를 성공적으로 호출**하여 잘못된 output root를 삭제했다.

**5단계 — 결과:**
- Kroma 체인 자체는 **롤백되지 않았음**
- 잘못된 output root만 삭제됨
- 정상적인 output root가 이후 재제출됨

```
[L1 Origin 문제]
      │
      ▼
[시퀀서: 잘못된 L2 블록 생성]
      │
      ▼
[밸리데이터: 잘못된 Output Root L1 제출]
      │
      ▼
[12명 Challenger 이의 제기]
      │
      ▼
[1명 proveFault 성공 → Output Root 삭제]
      │
      ▼
[체인 롤백 없음, 정상 Output 재제출]
```

#### 교훈

1. **Challenge 메커니즘은 실제로 동작한다**: 3년간 이론적으로만 존재하던 메커니즘이 실전에서 작동함을 증명
2. **다수의 Challenger가 필요**: 12명이 참여했지만 1명만 성공 — redundancy가 핵심
3. **ZK Fault Proof의 실효성**: Kroma의 ZK 기반 fault proof가 실제 환경에서 유효함을 입증
4. **체인 롤백 없이 Output만 교체 가능**: 사용자 경험에 미치는 영향 최소화

### 3.2 Arbitrum — Ethereum PoW 포크에서의 Challenge 성공

> **시기**: 2022년 9월 (The Merge 이후)

#### 사건 개요

| 항목 | 상세 |
|------|------|
| **환경** | Ethereum PoW 포크 위의 Arbitrum |
| **공격** | 누군가 PoW 포크 체인에서 전체 데이터 탈취 시도 |
| **결과** | Challenge를 통해 공격 차단 성공 |

#### 상세 분석

Ethereum이 PoS로 전환(The Merge)된 후, PoW 포크 체인이 잠시 유지되었다. 이 PoW 포크 위에서 운영되던 Arbitrum 버전에서 누군가 자금 탈취를 시도했고, **정직한 밸리데이터가 challenge를 제기하여 공격을 성공적으로 차단**했다.

이 사례는 비록 메인넷이 아닌 포크 체인에서 발생했지만, interactive fraud proof가 실제 적대적 환경에서 동작함을 보여준 최초의 사례 중 하나이다.

### 3.3 Optimism — Fault Proof 취약점 발견 및 대응 (2024년 8월)

> **이 사례는 Challenge 성공이 아닌, Challenge 시스템 자체의 취약점 발견 사례**

#### 사건 개요

| 항목 | 상세 |
|------|------|
| **날짜** | 2024년 8월 |
| **발견자** | Spearbit, Cantina, Code4rena (보안 감사) |
| **내용** | Permissionless Fault Proof System에서 고위험 취약점 2건 발견 |
| **대응** | Permissioned fallback 활성화 → Granite 하드포크 (2024.09.11) |
| **사용자 자산 피해** | 없음 (취약점은 악용되지 않음) |

#### 상세 분석

**발견된 취약점:**
- Fault Dispute Game의 해결(resolution) 메커니즘에서 2건의 고위험 취약점
- 잘못 해결된 FaultDisputeGame이 블랙리스트되더라도 향후 게임 배포를 방해할 수 있는 DoS 취약점
- 블랙리스트된 게임에 대해 증명된 출금이 확정되지 못하는 문제

**대응 타임라인:**
```
2024.06.10  Permissionless Fault Proof 메인넷 활성화
     │
2024.08.xx  보안 감사에서 고위험 취약점 2건 발견
     │
2024.08.xx  Permissioned fallback 활성화 (퍼미션리스 일시 중단)
     │
2024.08.12  Granite OP Sepolia 활성화
     │
2024.09.11  Granite OP Mainnet 활성화 (취약점 패치 + 퍼미션리스 재활성화)
```

#### 교훈

1. **Challenge 시스템 자체도 취약할 수 있다**: 보안 메커니즘도 보안 감사가 필요
2. **Permissioned fallback이 안전장치로 기능**: 위기 시 중앙화된 보호로 전환 가능
3. **코드 감사의 중요성**: 3개 감사 팀(Spearbit, Cantina, Code4rena)이 각각 다른 취약점 발견

---

## 4. Challenge가 발생하지 않은/실패한 주요 사례

### 4.1 대부분의 Optimistic Rollup — Challenge 미발생 (2021~2025)

> **"Arbitrum의 fraud proof는 론칭 후 2년간 한 번도 사용되지 않았다"** — CoinTelegraph

| 롤업 | 메인넷 론칭 | Challenge 발생 건수 (메인넷) |
|------|-----------|--------------------------|
| Arbitrum One | 2021년 5월 | 0건 (2025년 2월 BoLD 이전) |
| Optimism | 2021년 12월 | 0건 (정상적 Challenge) |
| Base | 2023년 8월 | 0건 |

**이유 분석:**
1. **허가형(Permissioned) 시스템**: 대부분의 롤업이 오랫동안 화이트리스트된 밸리데이터만 Challenge 가능하도록 운영
2. **중앙화된 시퀀서**: 시퀀서가 정직하게 동작하면 잘못된 상태 루트가 제출될 가능성이 극히 낮음
3. **경제적 억지력**: Challenge bond (Arbitrum 기준 1,110 ETH ≈ $3.5M+)가 충분한 억지력 제공
4. **실제 공격 대상이 아님**: 공격자가 Challenge 메커니즘을 우회하기보다 다른 벡터(브릿지, 스마트 컨트랙트)를 선호

### 4.2 Linea — 시퀀서 검열을 통한 보안 대응 (2024년 6월)

| 항목 | 상세 |
|------|------|
| **날짜** | 2024년 6월 |
| **사건** | Velocore 해킹 (Linea 위 DEX) |
| **대응** | Linea 시퀀서를 일시 정지하고 공격자 주소 검열 |
| **논란** | 탈중앙화 원칙 vs 보안 대응의 딜레마 |

이 사례는 Challenge 메커니즘이 아닌 **중앙화된 시퀀서의 검열 권한**을 통해 보안 대응이 이루어진 경우로, Challenge 메커니즘의 한계와 중앙화 리스크를 동시에 보여준다.

### 4.3 Optimistic Rollup의 구조적 한계 — Challenger 검열 시나리오

evmresearch.io에서 지적된 핵심 취약점:

> *"optimistic rollups can finalize invalid state when all challengers are censored"*
> *"forced inclusion mechanisms in optimistic rollups are insufficient against sequencer state manipulation"*

| 공격 시나리오 | 설명 | 현실 가능성 |
|-------------|------|-----------|
| **Challenger 검열** | 모든 challenger의 L1 트랜잭션을 검열하여 challenge period 경과 | 이론적 (L1 검열 필요) |
| **경제적 검열** | 블록 프로포저에게 뇌물을 제공하여 challenge 트랜잭션 제외 | 낮음 (MEV-Boost 환경) |
| **지연 공격** | 반복적으로 잘못된 challenge를 제기하여 정직한 출금 지연 | BoLD로 완화됨 |
| **시퀀서 조작** | 시퀀서가 강제 포함 메커니즘을 무력화 | 구조적 한계 존재 |

---

## 5. Rollup Stage별 현황 (L2Beat 기준, 2026년 3월)

### 5.1 Stage 분류 체계

| Stage | 설명 | 핵심 요건 |
|-------|------|----------|
| **Stage 0** | Full Training Wheels | 중앙화된 프로포저/챌린저, 사실상 신뢰 기반 |
| **Stage 1** | Limited Training Wheels | 퍼미션리스 fraud proof, Security Council 유지 |
| **Stage 2** | No Training Wheels | 완전 퍼미션리스, Security Council은 온체인 오류 시에만 개입 |

### 5.2 주요 Rollup Stage 현황

| Rollup | Stage | Fraud Proof | 퍼미션리스 | 비고 |
|--------|-------|-------------|-----------|------|
| **Arbitrum One** | Stage 1 | BoLD | Yes (2025.02~) | 최대 TVL |
| **OP Mainnet** | Stage 1 | FPS (Cannon) | Yes (2024.06~) | Granite 패치 완료 |
| **Base** | Stage 1 | FPS (OP Stack) | Yes (2025.06~) | Coinbase 운영 |
| **Cartesi** | Stage 2 | 자체 | Yes | 2025년 Stage 2 달성 |
| **Kroma** | Stage 1 | ZK Fault Proof | Yes | 최초 Challenge 성공 |
| **Blast** | Stage 0 | 제한적 | No | 중앙화 |
| **Mantle** | Stage 0 | 제한적 | No | 자체 DA |
| **Linea** | Stage 0 | 없음 | No | ZK Rollup으로 전환 중 |

---

## 6. 분석 및 시사점

### 6.1 Challenge 성공 사례 요약

| # | 사례 | 날짜 | 환경 | 유형 | 결과 |
|---|------|------|------|------|------|
| 1 | **Kroma Output Root 삭제** | 2024.04.01 | 메인넷 | 시퀀서 오류 → 잘못된 Output | **성공** (역사상 최초) |
| 2 | **Arbitrum PoW 포크 방어** | 2022.09 | PoW 포크 | 자금 탈취 시도 | **성공** |
| 3 | **Optimism FPS 취약점 대응** | 2024.08 | 메인넷 | 시스템 취약점 발견 | 퍼미션 전환으로 대응 |

### 6.2 핵심 시사점

#### Challenge가 거의 발생하지 않는 이유

1. **억지력(Deterrence) 효과**: Challenge 메커니즘의 존재 자체가 악의적 행위를 방지
2. **중앙화된 운영**: 대부분의 시퀀서가 단일 주체에 의해 정직하게 운영됨
3. **높은 참여 비용**: Challenge bond가 수백~수천 ETH로 진입 장벽이 높음
4. **허가형 시스템**: 최근까지 대부분의 롤업이 화이트리스트 기반 challenge만 허용

#### 보안 관점에서의 우려

1. **실전 검증 부족**: 3년간 1건의 실제 성공 사례만 존재 — 시스템이 대규모 공격에서도 동작할지 불확실
2. **Challenge 시스템 자체의 취약점**: Optimism FPS 감사에서 고위험 취약점 발견 — 보안 메커니즘도 보안 감사 필요
3. **검열 저항성 미흡**: Challenger가 검열당하면 잘못된 상태가 확정될 수 있음
4. **경제적 공격**: 대규모 자금을 가진 공격자가 Challenge bond를 감당하면서 지연 공격 가능
5. **중앙화된 대응에 의존**: Linea 사례처럼 시퀀서 정지로 대응하는 것이 실질적 방어

#### 향후 전망

1. **Stage 2 달성**: 더 많은 롤업이 완전 퍼미션리스 challenge를 구현할 것
2. **ZK 전환**: Optimistic Rollup이 점진적으로 ZK proof로 전환하는 추세
3. **Challenge 비용 절감**: BoLD 등 새로운 프로토콜이 참여 비용을 낮추려 시도
4. **Watchdog 인프라**: 자동화된 challenger 인프라 구축이 핵심 과제

### 6.3 교육적 활용 포인트

| 주제 | 강의 활용 |
|------|----------|
| **Kroma 사례** | Challenge 메커니즘의 실제 동작 과정을 단계별로 분석 |
| **Arbitrum PoW 포크 사례** | 적대적 환경에서 interactive fraud proof의 효과 |
| **Optimism 취약점** | Challenge 시스템 자체의 보안 감사 필요성 |
| **Linea 검열** | 탈중앙화 vs 보안의 트레이드오프 토론 자료 |
| **Challenger 검열 시나리오** | CTF 문제 설계 소재 (evmresearch.io 연결) |

---

## 7. 참고 자료

### 기술 문서
- [Optimism Fault Proof Specification](https://specs.optimism.io/fault-proof/stage-one/fault-dispute-game.html)
- [Arbitrum BoLD Documentation](https://docs.arbitrum.io/how-arbitrum-works/bold/gentle-introduction)
- [OP-Challenger Documentation](https://docs.optimism.io/stack/fault-proofs/challenger)
- [Arbitrum Challenge Manager](https://docs.arbitrum.io/how-arbitrum-works/fraud-proofs/challenge-manager)

### 분석 자료
- [Fraud Proof Wars — L2BEAT](https://medium.com/l2beat/fraud-proof-wars-b0cb4d0f452a)
- [The State of Fraud Proofs in Ethereum L2s — Gate Research](https://www.gate.com/learn/articles/the-state-of-fraud-proofs-in-ethereum-l2s/4402)
- [State of Optimistic Proof — Four Pillars](https://4pillars.io/en/articles/state-of-optimistic-proof-will-zk-replace-it)
- [Fraud Proofs: The Eclipse Perspective](https://www.eclipselabs.io/blogs/fraud-proofs-the-eclipse-perspective)

### 보안 감사
- [Optimism Fault Proof — Code4rena Audit (2024.07)](https://github.com/code-423n4/2024-07-optimism)
- [Optimism Fault Proof — Sherlock Audit (2024.02)](https://github.com/sherlock-audit/2024-02-optimism-2024)
- [Fault Proofs 101 — Hacken](https://hacken.io/discover/fault-proofs/)
- [Dispute Games On-Chain Resolution — Hacken](https://hacken.io/discover/dispute-games/)

### L2 현황 트래커
- [L2Beat Stages](https://l2beat.com/stages)
- [L2Beat Rollup Comparison](https://l2beat.com/scaling/tvs)

### 뉴스 및 발표
- [OP Mainnet Fault Proofs — The Block](https://www.theblock.co/post/299202/op-mainnet-fault-proofs)
- [Permissionless Fault Proofs and Stage 1 — Optimism Blog](https://www.optimism.io/blog/permissionless-fault-proofs-and-stage-1-arrive-to-the-op-stack)
- [Arbitrum BoLD Mainnet — The Block](https://www.theblock.co/post/340278/offchain-labs-releases-arbitrum-bold-on-mainnet-for-permissionless-validation)
- [Optimism Granite Hard Fork — BeInCrypto](https://beincrypto.com/optimism-plans-hard-fork-to-fix-vulnerability/)
- [Kroma L2BEAT](https://l2beat.com/scaling/projects/kroma)

### 학술 자료
- [Economics of Disputes in Rollups — arXiv (2025.02)](https://arxiv.org/pdf/2502.20334)
- [Towards a Formal Foundation for Blockchain ZK Rollups](https://www.doc.ic.ac.uk/~livshits/papers/pdf/ccs25.pdf)

---

> **결론**: 2024년 4월 Kroma의 사례가 이더리움 롤업 역사상 **최초이자 유일하게 확인된 메인넷 Challenge 성공 사례**이다. Arbitrum PoW 포크에서의 성공 사례가 하나 더 존재하지만, 이는 메인넷이 아닌 포크 환경에서 발생했다. Optimistic Rollup의 Challenge 메커니즘은 대부분 **억지력(deterrence)**으로 기능하며, 실제 발동된 사례는 극히 드물다. 이는 시스템이 잘 동작해서일 수도, 충분히 검증되지 않아서일 수도 있다 — 이 질문이 향후 롤업 보안 연구의 핵심 주제이다.
