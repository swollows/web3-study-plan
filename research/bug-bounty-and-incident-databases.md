# Web3 버그바운티 플랫폼 및 사고 사례 데이터베이스 종합 가이드

## 개요

Web3 보안 생태계는 전통적인 사이버보안과 다른 독특한 구조를 갖는다. 코드가 공개되어 있고, 자금이 직접 위험에 노출되며, 수정 배포가 어렵다. 이 가이드는 버그바운티 플랫폼의 상세 운영 방식, 과거 사고 사례 데이터베이스, 한국 Web3 보안 생태계, 그리고 2024-2026년 주요 사고 타임라인을 다룬다.

---

## Part 1: 글로벌 Web3 버그바운티 플랫폼

### 1. Immunefi

**플랫폼 개요**

Immunefi는 Web3 버그바운티의 사실상 표준 플랫폼이다. 2020년 설립 이후 DeFi, NFT, 블록체인 인프라 전반에 걸쳐 가장 큰 규모의 화이트햇 해커 커뮤니티를 보유하고 있다.

- 총 지급액: $110M+ (2025년 기준, 누적)
- 최고 단일 포상: $10,000,000 (Wormhole 브리지, 2022)
- 등록 연구자: 45,000명+
- 활성 프로그램: 180개+
- 보호 자산 규모: $250B+

**포상금 체계**

| 등급 | 스마트 컨트랙트 | 블록체인/DLT | 웹/앱 |
|------|--------------|------------|-------|
| Critical | $50K ~ $10M | $50K ~ $10M | $10K ~ $50K |
| High | $10K ~ $100K | $10K ~ $100K | $5K ~ $10K |
| Medium | $1K ~ $10K | $1K ~ $10K | $1K ~ $5K |
| Low | $100 ~ $1K | $100 ~ $1K | $100 ~ $1K |

**프로그램 등록 절차**
1. 회원가입 및 프로필 작성 (전문 분야, 경력)
2. KYC 완료 (포상금 $1K 이상 지급 전 필수)
3. 원하는 프로그램 선택 → 범위(Scope) 확인
4. 취약점 발견 → 72시간 내 초기 응답 대기
5. 트리아지 → 수정 → 포상금 지급 (평균 28일)

**주요 지급 사례**

| 날짜 | 프로토콜 | 포상금 | 취약점 유형 |
|------|---------|--------|-----------|
| 2022.02 | Wormhole | $10M | 서명 검증 우회 |
| 2022.12 | Aurora | $6M | ETH 무한 발행 |
| 2021.10 | Polygon | $2M | MRC20 트랜잭션 우회 |
| 2022.09 | Optimism | $2M | 무한 ETH 발행 |
| 2023.06 | LayerZero | $15M | 크로스체인 메시지 위조 |
| 2023.12 | Scroll | $500K | ZK 회로 취약점 |
| 2024.03 | Blast | $200K | 출금 로직 버그 |

**Immunefi 연구자 팁**
- 최대 포상금이 큰 프로그램이 경쟁도 높다
- 새로 등록된 프로그램은 경쟁이 낮아 초보에게 유리
- 같은 취약점을 여러 체인에서 발견하면 각각 별도 보고
- 코드 변경 후 새 취약점이 생기는 경우 주시
- 프로그램의 "Out of Scope" 항목 반드시 확인
- PoC(Proof of Concept) 코드 첨부 시 수락률 상승

**보고서 작성 필수 요소**

```markdown
## 취약점 요약
[2-3문장으로 핵심 설명]

## 심각도
Critical / High / Medium / Low

## 취약한 컨트랙트
- 파일: src/core/Pool.sol
- 함수: withdraw()
- 줄 번호: L142-L157

## 공격 시나리오
1단계: ...
2단계: ...

## 영향
- 자금 손실 가능액: $X
- 영향 받는 사용자: 모든 예치자

## PoC
```solidity
// forge test --match-test testExploit --fork-url $ETH_RPC
```

## 수정 권고안
[구체적인 코드 레벨 수정 제안]
```

---

### 2. Code4rena

**플랫폼 개요**

Code4rena는 경쟁적 감사(competitive audit) 모델을 도입한 플랫폼이다. 프로젝트가 감사 풀을 설정하면 다수의 연구자(Warden)가 동시에 감사하여 각자 발견한 취약점을 제출한다.

- 설립: 2021년
- 총 지급액: $40M+ (누적)
- 활성 Warden: 5,000명+
- 평균 감사 기간: 3-14일
- URL: https://code4rena.com

**Warden 등급 체계**

```
일반 Warden
    ↓ (지속적 유효 제출)
Senior Warden
    ↓ (높은 심각도 발견 + 리더십)
Top Warden (리더보드 상위)
    ↓ (초대)
Judge / Validator (심사 역할)
```

**포상금 분배 공식**

High 취약점:
- 최초 발견 + 유일한 발견: 전체 High 풀의 단독 수령
- n명이 같은 취약점 발견: 풀 / n (일부 중복 감산)

Medium 취약점:
- High와 유사하나 풀 크기가 작음

QA 리포트:
- Low/Gas/Informational 종합 리포트
- 상위 10% 리포트에 QA 풀 배분

**효율적 감사 전략**

```
1단계 (1일): 스코프 파악
  - SLOC(Source Lines of Code) 확인
  - 외부 의존성 목록화
  - 상속 구조 다이어그램
  - 테스트 커버리지 확인
  - 이전 감사 보고서 검토

2단계 (2-3일): 심층 분석
  - 가장 복잡한 컨트랙트부터
  - 자금이 이동하는 모든 경로
  - 접근 제어 매트릭스
  - 외부 호출 목록화
  - 상태 변수 변경 추적

3단계 (마지막 날): 정리
  - QA 리포트 작성
  - Gas 최적화 제안
  - 보고서 형식 맞추기
  - PoC 코드 완성
```

---

### 3. Sherlock

**플랫폼 개요**

Sherlock은 감사(audit) + 커버리지(보험) 복합 모델로 차별화된다. 감사를 통과한 프로토콜에 커버리지를 제공하며, 커버리지 풀은 Warden들이 스테이킹으로 조성한다.

- 설립: 2021년
- 총 지급액: $10M+ (감사 포상)
- 커버리지 지급: $10M+ (실제 해킹 피해 보상)
- URL: https://sherlock.xyz

**Watson 등급**

| 등급 | 조건 | 혜택 |
|------|-----|------|
| Watson | 기본 가입 | 모든 감사 참여 |
| Senior Watson | 지속적 유효 제출 | 추가 포상금 배율 |
| Lead Senior Watson | 초대 | 감사 리드, 분쟁 판정 참여 |

**분쟁 해결 프로세스**
1. Watson이 취약점 제출
2. Lead Warden이 중요도 분류
3. 이의 제기(escalation) 가능
4. Sherlock 판사(Judge)가 최종 결정
5. 잘못된 이의 제기 시 페널티

**보험 모델의 의미**

Sherlock이 감사한 프로토콜에서 해킹 발생 시:
- 프로토콜이 커버리지 풀에서 피해액 보상 가능
- Watson들의 스테이킹 자금이 보상에 사용됨
- 잘못 감사한 Watson은 스테이킹 손실 (경제적 인센티브 정렬)

---

### 4. Hats Finance

**플랫폼 개요**

완전 탈중앙화 버그바운티 프로토콜. 프로토콜팀이 스마트 컨트랙트에 직접 포상금 풀을 생성하고, 제출-트리아지-지급이 모두 온체인으로 처리된다.

- 온체인 거버넌스 기반
- 포상금 풀: ERC20 토큰으로 직접 예치
- 중개자 없는 완전 자동화
- GitHub: https://github.com/hats-finance/hats-contracts
- URL: https://hats.finance

**동작 원리**
```
1. 프로젝트: createVault(token, amount, committee[])
2. 연구자: submitVulnerability(vaultId, description, pocHash)
3. 위원회(committee): approve/reject 투표 (일반적으로 72시간)
4. 승인 시: 자동 포상금 지급 (스마트 컨트랙트 실행)
5. 거부 시: 항소 가능
```

**장단점**
- 장점: 중개자 없음, 검열 저항성, 자동 지급
- 단점: 위원회가 악의적일 경우 제출 거부 가능, 복잡한 취약점 평가 어려움

---

### 5. HackerOne Web3 프로그램

전통적인 버그바운티 플랫폼 HackerOne도 Web3 분야에 진출했다.

**주요 Web3 프로그램**
- Ethereum Foundation (인프라, 클라이언트)
- Coinbase (거래소, 지갑)
- Binance (거래소, BNB Chain)
- Kraken (거래소)
- Uniswap Labs (웹 인터페이스)
- Chainlink Labs (오라클 인프라)
- Consensys (MetaMask, Infura)

**특징**
- 전통 보안(웹, API, 인프라) + 스마트 컨트랙트 혼합
- 대기업 프로그램이 많아 응답 속도 빠름
- 스마트 컨트랙트 단독보다 인프라 포함 프로그램 다수
- 포상금 분쟁 시 HackerOne 중재 가능

---

### 6. Cantina (Spearbit)

**플랫폼 개요**

Spearbit이 운영하는 초고급 감사 플랫폼. 검증된 최상위 감사자만 참여할 수 있어 경쟁률은 낮지만 진입 장벽이 높다.

- Cantina URL: https://cantina.xyz
- 감사자 심사: 포트폴리오 + 레퍼런스 체크
- 감사 형식: 팀 기반 경쟁 감사
- 포상금: 업계 최상위 수준

**참여 조건**
- Code4rena/Sherlock에서 검증된 트랙 레코드
- 최소 2건의 Critical 발견 이력 또는
- 알려진 감사 회사에서의 경력
- 기술 인터뷰 통과

**Spearbit 리서치**
- 독립적인 보안 연구 발행
- EIP/ERC 보안 분석
- Uniswap, Blur 등 대형 프로토콜 감사 이력

---

### 7. Codehawks (Cyfrin)

**플랫폼 개요**

Patrick Collins(Cyfrin)가 설립한 감사 플랫폼. 교육 콘텐츠와 연계되어 초중급 연구자 친화적이다.

- URL: https://www.codehawks.com
- 특징: First Flight(연습용 소규모 감사) 제도
- 커뮤니티: Patrick Collins 유튜브 구독자 기반

**First Flight 프로그램**
- 소규모 코드베이스로 연습
- 포상금은 적지만 경험 쌓기에 최적
- 매주 새로운 코드베이스 공개
- 초보 연구자에게 실전 환경 제공

**Aderyn 정적 분석 도구**
```bash
# Cyfrin 개발 오픈소스 분석 도구
cargo install aderyn
aderyn .

# 출력: markdown 형식의 취약점 보고서
# Slither와 유사하나 Rust 기반으로 빠름
```

---

## Part 2: 사고 사례 DB & 트래커

### 1. rekt.news

**개요**

DeFi 해킹 사고를 저널리즘 형식으로 기록하는 독립 미디어. 사고 직후 빠른 분석 기사를 발행하며, 누적 손실액 순으로 리더보드를 유지한다.

- URL: https://rekt.news
- 리더보드: https://rekt.news/leaderboard
- 업데이트: 주요 사고 발생 시 수시

**rekt 리더보드 상위 사고 (2026년 기준)**

| 순위 | 프로토콜 | 손실액 | 날짜 |
|------|---------|--------|------|
| 1 | Bybit | $1.5B | 2025.02 |
| 2 | Ronin Network | $625M | 2022.03 |
| 3 | Poly Network | $611M | 2021.08 |
| 4 | BNB Chain Bridge | $570M | 2022.10 |
| 5 | Wormhole | $320M | 2022.02 |
| 6 | Nomad | $190M | 2022.08 |
| 7 | Euler Finance | $197M | 2023.03 |
| 8 | Beanstalk | $182M | 2022.04 |
| 9 | Multichain | $126M | 2023.07 |
| 10 | Orbit Chain | $82M | 2024.01 |

---

### 2. DeFiHackLabs (SunWeb3Sec)

**개요**

실제 DeFi 해킹을 Foundry PoC로 재현한 오픈소스 저장소. 보안 교육 목적으로 가장 많이 사용되는 자료 중 하나다.

- GitHub: https://github.com/SunWeb3Sec/DeFiHackLabs
- 재현 사고 수: 400건+ (2025년 기준)
- 언어: Solidity (Foundry)
- 라이선스: MIT

**사용 방법**
```bash
git clone https://github.com/SunWeb3Sec/DeFiHackLabs
cd DeFiHackLabs

# 특정 해킹 재현
forge test --match-contract EulerHack --fork-url $ETH_RPC \
    --fork-block-number 16817996 -vvv

# 전체 테스트 (느림)
forge test --fork-url $ETH_RPC -vv
```

**카테고리별 분류**
- Reentrancy: 40건+
- Flash Loan: 80건+
- Price Oracle: 60건+
- Access Control: 50건+
- Business Logic: 70건+
- Rug Pull: 30건+

---

### 3. Solodit

**개요**

감사 보고서와 버그바운티 제출물을 집계한 데이터베이스. 발견된 취약점을 유형별, 프로토콜별, 심각도별로 검색할 수 있다.

- URL: https://solodit.xyz
- 데이터 소스: Code4rena, Sherlock, Spearbit, Trail of Bits 등
- 검색: 취약점 유형, 프로토콜, 날짜 범위

**활용 방법**
- 특정 유형 취약점(예: reentrancy) 검색 → 실제 발견 패턴 학습
- 특정 프로토콜 감사 이력 → 유사 프로토콜 감사 시 참고
- 최근 High/Critical 트렌드 → 현재 감사 시 집중 영역 파악

---

### 4. DeFi Llama Hacks

- URL: https://defillama.com/hacks
- 데이터: 날짜, 프로토콜, 손실액, 체인, 공격 유형
- 체인별/유형별 필터, 연도별 통계, 자금 회수 여부 추적

---

### 5. SlowMist Hacked

- URL: https://hacked.slowmist.io
- 아시아 프로젝트 사고 커버리지 강함
- 연간 보안 보고서 발행 (무료 PDF)

---

### 6. Chainalysis Reports

- URL: https://www.chainalysis.com/reports
- Crypto Crime Report (연간), 랜섬웨어, 자금세탁, 다크넷 통계
- 2024 기준: DeFi 해킹 $1.4B, 북한 Lazarus $800M+

---

### 7. L2Beat

- URL: https://l2beat.com
- L2 TVL, 업그레이드 리스크, 중앙화 리스크 정량화
- State Validation, Data Availability, Upgradeability, Sequencer Failure 지표

---

## Part 3: 한국 Web3 보안

### ChainLight (구 Theori Web3)

**개요**

한국 최정상급 보안 회사 Theori의 Web3 보안 부문. 2023년 ChainLight로 분사하여 독립 운영한다.

- 웹사이트: https://chainlight.io
- 전문 분야: 스마트 컨트랙트 감사, 버그바운티, 포렌식
- 주요 클라이언트: 카카오(클레이튼), 라인(핀시아), 국내 주요 거래소

**주요 발견 사례**
- Klaytn 생태계 다수 취약점 발견 및 보고
- 해외 주요 DeFi 프로토콜 감사 참여
- Immunefi에서 다수 화이트햇 제출

**팀 구성**
- 기존 Theori의 시스템 해킹, 웹 보안 전문가들이 Web3로 전환
- KAIST, SNU, POSTECH 등 국내 명문대 출신 연구자

---

### S2W (구 에스이더블유)

AI 기반 위협 인텔리전스 회사. 다크웹 모니터링과 블록체인 포렌식 분야에서 강점.

- 웹사이트: https://www.s2w.inc
- 전문 분야: 블록체인 포렌식, 암호화폐 추적, 위협 인텔리전스
- 협력: 국내 수사기관, 거래소

---

### KAIST 블록체인 보안 연구

- KAIST 사이버보안연구센터 (CSRC)
- EVM 정적 분석, DeFi 취약점 자동 탐지, 프라이버시 연구
- SmartDagger, SMARTIAN 등 퍼징 도구 개발

---

### Sooho.io

- 스마트 컨트랙트 감사 전문
- 국내 DeFi, NFT 프로젝트 다수 감사 이력
- 자동화 분석 도구 병행

---

### 한국 CTF 팀 및 커뮤니티

**주요 팀**
- **KAIST GoN (Ghost of Nuke)**: DEFCON CTF 상위권 팀, Web3 트랙 참여
- **SeoulTech 0xBB**: Web3 CTF 특화 신생 팀
- **Theori/BestOfBest 파생팀**: 전통 + Web3 하이브리드

**온라인 커뮤니티**
- 카카오톡: "Web3 Korea Security" 오픈채팅
- Discord: 한국 블록체인 개발자 서버
- Secureum RACE 한국 스터디 그룹

**국내 버그바운티 프로그램**
- 카카오(클레이튼) - Immunefi 등록
- 라인(핀시아) - 자체 프로그램
- 코인원, 업비트, 빗썸 - HackerOne 또는 자체
- SK C&C, 삼성 SDS - 엔터프라이즈 블록체인 보안

---

## Part 4: 2024-2026 주요 사고 타임라인

### 연도별 총계

| 연도 | 총 손실액 | 주요 사고 수 | 가장 큰 단일 사고 |
|------|---------|-----------|----------------|
| 2021 | $3.2B | 250+ | Poly Network ($611M) |
| 2022 | $3.8B | 300+ | Ronin Network ($625M) |
| 2023 | $1.7B | 280+ | Euler Finance ($197M) |
| 2024 | $2.2B | 310+ | Radiant Capital ($58M) |
| 2025 | $2.8B+ | 180+ | Bybit ($1.5B) |

---

### 2024년 월별 사고 타임라인

| 날짜 | 프로토콜 | 체인 | 손실액 | 공격 유형 | 자금 회수 |
|------|---------|------|--------|----------|----------|
| 2024.01.02 | Orbit Chain | Ethereum | $82M | 다중서명 키 탈취 | 일부 동결 |
| 2024.01.12 | Gamma Strategies | Arbitrum | $3.4M | 가격 조작 | 0% |
| 2024.01.22 | Radiant Capital (1차) | Arbitrum | $4.5M | 플래시론 + 재진입 | 0% |
| 2024.01.23 | Socket Protocol | Multi | $3.3M | 입력값 검증 누락 | 전액 회수 |
| 2024.01.30 | MIM Spell | Ethereum | $6.5M | 정수 반올림 오류 | 0% |
| 2024.02.03 | Abracadabra Money | Ethereum | $6.5M | 이자율 누산 버그 | 0% |
| 2024.02.09 | Seneca Protocol | Ethereum | $6.5M | 임의 외부 호출 | 80% 회수 |
| 2024.02.21 | Blueberry Protocol | Ethereum | $1.3M | 화이트햇 선점 | 전액 반환 |
| 2024.03.28 | Prisma Finance | Ethereum | $11.6M | 플래시 대출 + 재진입 | 0% |
| 2024.04.02 | FixedFloat | BTC/ETH | $3M | 인프라 침해 | 0% |
| 2024.04.19 | Pike Finance (1차) | Multi | $1.7M | USDC 크로스체인 버그 | 0% |
| 2024.04.26 | Pike Finance (2차) | Multi | $1.6M | 접근 제어 (동일 취약점) | 0% |
| 2024.04.30 | Renzo Protocol | Ethereum | $0 | 디페깅 (기술 버그 아님) | N/A |
| 2024.05.15 | ALEX Lab | Bitcoin L2 | $4.3M | 프라이빗 키 탈취 | 일부 |
| 2024.05.20 | Sonne Finance | Optimism | $20M | ERC4626 컴파운딩 취약점 | 0% |
| 2024.05.26 | Hedgey Finance | Multi | $44.7M | 접근 제어 (토큰 클레임) | 0% |
| 2024.06.11 | DMM Bitcoin | Bitcoin | $305M | 프라이빗 키 탈취 (Lazarus) | 0% |
| 2024.06.12 | UwU Lend (1차) | Ethereum | $19.3M | 가격 오라클 조작 | 0% |
| 2024.06.16 | UwU Lend (2차) | Ethereum | $3.7M | 동일 공격자 재공격 | 0% |
| 2024.06.20 | Velocore | Linea/zkSync | $6.8M | 재진입 | 0% |
| 2024.07.10 | Munchables | Blast | $62.5M | 내부자 (계약직 개발자) | 전액 반환 |
| 2024.07.18 | LI.FI Protocol | Multi | $10M | 임의 calldata 실행 | 0% |
| 2024.07.18 | Rho Markets | Scroll | $7.6M | 오라클 오설정 | 전액 반환 |
| 2024.07.19 | WazirX | Ethereum | $235M | 다중서명 UI 조작 (Lazarus) | 0% |
| 2024.08.05 | Ronin Network (2차) | Ethereum | $12M | MEV 봇 오류 | 전액 반환 |
| 2024.08.22 | Nexera | BSC | $1.5M | 접근 제어 | 0% |
| 2024.09.03 | Penpie | Ethereum | $27M | 재진입 + 플래시론 | 0% |
| 2024.09.19 | BingX | Multi | $45M | 핫월렛 침해 | 일부 동결 |
| 2024.09.25 | Banana Gun | Telegram | $3M | 서명 재사용 | 0% |
| 2024.09.26 | Indodax | Multi | $20M | 인프라 침해 | 0% |
| 2024.10.01 | Onyx Protocol | Ethereum | $3.8M | 컴파운드 포크 취약점 | 0% |
| 2024.10.16 | Radiant Capital (2차) | Multi | $58M | 다중서명 기기 감염 (Lazarus) | 0% |
| 2024.10.30 | M2 Exchange | Multi | $13.7M | 인프라 침해 | 전액 회수 |
| 2024.11.04 | DeltaPrime | Avalanche | $4.8M | 접근 제어 | 0% |
| 2024.11.11 | PlayDapp (2차) | Ethereum | $290M | 프라이빗 키 탈취 | 0% |
| 2024.11.26 | Metawin | Ethereum | $4M | 핫월렛 침해 | 0% |
| 2024.12.09 | Clipper DEX | Multi | $6.5M | 서명 검증 | 0% |
| 2024.12.16 | Hyperliquid | Solana | $0 (위기) | Lazarus 자금 이동 감지 | N/A |
| 2024.12.23 | GemPad | Multi | $2.1M | 재진입 | 0% |

---

### 2025년 주요 사고 타임라인

| 날짜 | 프로토콜 | 체인 | 손실액 | 공격 유형 | 비고 |
|------|---------|------|--------|----------|-----|
| 2025.01.15 | Moby Trade | Arbitrum | $2.5M | 프라이빗 키 노출 | - |
| 2025.01.24 | Phishing Wave | Multi | $10M+ | 피싱 (사용자 서명 탈취) | 복수 프로젝트 |
| 2025.02.21 | **Bybit** | Ethereum | **$1.5B** | 다중서명 UI 위조 (Lazarus) | 역대 최대 |
| 2025.02.26 | zkLend | Starknet | $9.6M | 고정소수점 정밀도 버그 | - |
| 2025.03.04 | Infini | Ethereum | $49.5M | 접근 제어 (전직 개발자) | 내부자 |
| 2025.03.12 | 1inch | Ethereum | $5M | 서명 재사용 (Resolver) | - |
| 2025.03.26 | Zoth | Ethereum | $8.4M | 업그레이드 악용 | RWA 프로토콜 |
| 2025.04.01 | KiloEx | BSC/Base | $7.5M | 가격 오라클 조작 | - |
| 2025.04.14 | Loopscale | Solana | $5.8M | 담보 평가 조작 | - |
| 2025.04.25 | zkSync | Ethereum | $5M | 관리자 에어드랍 오류 | 전액 반환 |
| 2025.05.12 | Cetus Protocol | Sui | $223M | AMM 수학 오버플로우 | 부분 동결 |

---

### 주요 사고 상세 분석

#### Bybit $1.5B 해킹 (2025.02.21) — 역대 최대

**공격 방법:**

북한 Lazarus Group이 Safe{Wallet} (구 Gnosis Safe) 다중서명 인터페이스 공급망을 침해했다.

```
공격 체인:
1. Safe{Wallet} 프론트엔드 빌드 파이프라인 침해
   (개발자 노트북 또는 CI/CD 서버 침해 추정)

2. 특정 주소(Bybit cold wallet)를 타겟으로 하는
   악성 JavaScript 삽입

3. Bybit 직원들이 정상 ETH 이전처럼 보이는
   트랜잭션에 서명 (UI에서 내용 위조)

4. 실제 트랜잭션:
   safe.execTransaction() ->
   Implementation 교체 (upgradeTo(maliciousImpl))

5. 악성 구현으로 $1.5B ETH 인출
```

**기술적 세부사항:**

```solidity
// 정상적으로 보이는 트랜잭션 (UI 표시):
// "Transfer 100 ETH to 0xabc..."

// 실제 실행된 트랜잭션:
safe.execTransaction(
    to: address(safe),  // Safe 자신에게
    value: 0,
    data: abi.encodeWithSignature(
        "upgradeTo(address)",
        maliciousImplementation  // 악성 구현으로 교체
    ),
    operation: DelegateCall,
    // ... 5개 서명 첨부 (탈취된 것 아님 - 실제 서명자들이 서명)
);

// 교체 후 악성 구현:
function drainFunds(address recipient) external {
    // 모든 ETH/ERC20 전송
    payable(recipient).transfer(address(this).balance);
}
```

**시사점:**
- 다중서명 자체는 안전하더라도 프론트엔드 공급망이 침해되면 무력화
- 서명 전 트랜잭션 내용의 독립적 검증 필요 (calldata 직접 확인)
- Hardware wallet 연결 + 독립 노드 + calldata 디코더 사용
- 공급망 보안(npm 패키지, CI/CD) 강화 필요

---

#### WazirX $235M 해킹 (2024.07.19)

```
구조: Safe 다중서명 (4/6 서명 필요)
공격: Bybit와 유사한 UI 조작 공격

1. Liminal (수탁 서비스) 인터페이스 침해
2. WazirX 서명자들이 정상 트랜잭션으로 착각하고 서명
3. 실제 트랜잭션: Safe 구현 교체
4. $235M USDT/ETH/SHIB 등 탈취

특이사항:
- WazirX와 Liminal이 서로 책임 공방
- Lazarus Group 특징적 자금 세탁 패턴 확인
- 인도 거래소 최대 해킹 사고
```

---

#### Munchables $62.5M (2024.07.10) — 전액 반환

```
특이 사례: 내부자 공격 → 완전 반환

1. Blast 생태계 게임 프로토콜
2. 계약직 개발자(북한 국적 추정)가 업그레이드 가능한
   컨트랙트에 백도어 삽입
3. 배포 후 $62.5M 탈취
4. 커뮤니티 압박 + 법적 위협 후 전액 반환
   (프라이빗 키 제공 형태)

교훈:
- 계약직/외부 개발자 신원 확인 강화
- 업그레이드 가능 컨트랙트 배포 전 전면 감사
- 다중서명 + 타임락으로 업그레이드 통제
```

---

#### Radiant Capital $58M (2024.10.16) — Lazarus

```
공격 벡터: 다중서명 하드웨어 지갑 감염

1. 팀 멤버 3명의 하드웨어 지갑/컴퓨터 감염
   (Telegram DM으로 악성 PDF 전달)

2. 감염된 프론트엔드가 정상 트랜잭션 서명 요청처럼 위장

3. 실제: Radiant의 Lending Pool 소유권 이전 트랜잭션

4. 소유권 획득 후 모든 자산 드레인

피해: Arbitrum $32M + BSC $26M

방어 개선:
- 서명 전 calldata 독립 검증 시스템 도입
- 3개 이상의 물리적으로 분리된 기기에서 검증
- Tenderly 시뮬레이션 의무화
```

---

#### Penpie $27M (2024.09.03)

```
취약점: 재진입 + 플래시론 복합

1. Penpie = Pendle의 수익 최적화 프로토콜
2. Pendle의 새로운 SY(Standardized Yield) 토큰 타입 지원
3. 공격자가 악성 SY 토큰 등록

공격 흐름:
1. 플래시론으로 대량 PT/YT 획득
2. depositMarket() 호출 (악성 SY 토큰 사용)
3. 악성 SY.deposit() 콜백에서 재진입
4. claimRewards()가 이미 예치된 것처럼 처리
5. 실제 예치 없이 보상 청구

Pendle 프로토콜 자체는 안전, Penpie 통합 레이어 취약
```

---

#### Orbit Chain $82M (2024.01.02)

```
구조: 한국 기반 크로스체인 브리지
공격: 다중서명 검증자 키 탈취 (Lazarus 추정)

피해:
- USDT $30M
- DAI $10M
- WBTC 231개
- USDC $9.8M
- ETH 9,500개

현황:
- 일부 자금 Tornado Cash로 세탁
- Tether/Circle이 일부 자산 동결
- 한국 경찰청 수사 진행
```

---

#### DMM Bitcoin $305M (2024.06.11)

```
일본 암호화폐 거래소 DMM Bitcoin의 역대 최대 사고.

공격: 프라이빗 키 탈취 (Lazarus Group 확인)
피해: BTC 4,502개 (약 $305M)

Chainalysis의 자금 추적:
1. 탈취 BTC가 여러 주소로 분산
2. 믹서 사용
3. 캄보디아 소재 거래소 Huione Guarantee로 일부 이동
   (Lazarus의 주요 자금세탁 창구)

결과:
- DMM Bitcoin 2024년 12월 파산 신청
- SBI VC Trade에 고객 자산 이전
```

---

#### Hedgey Finance $44.7M (2024.05.26)

```
취약점: 토큰 클레임 컨트랙트의 접근 제어 부재

공격 흐름:
1. TokenClaim 컨트랙트의 createLockedCampaign() 함수
2. 수혜자 목록 검증 없이 임의 토큰 클레임 가능
3. 공격자가 자신을 수혜자로 등록 후 즉시 클레임

영향:
- Ethereum: $42.8M
- Arbitrum: $1.9M
- 총 47개 프로젝트의 토큰 클레임 컨트랙트 영향
```

---

### 2024년 공격 유형별 통계

| 공격 유형 | 사고 수 | 총 손실액 | 평균 손실액 |
|----------|--------|---------|-----------|
| 프라이빗 키/인프라 탈취 | 45 | $680M | $15.1M |
| 다중서명 침해 | 12 | $490M | $40.8M |
| 접근 제어 취약점 | 55 | $240M | $4.4M |
| 논리 버그 | 42 | $320M | $7.6M |
| 플래시론 + 오라클 조작 | 38 | $180M | $4.7M |
| 재진입 | 28 | $95M | $3.4M |
| 내부자 | 8 | $95M | $11.9M |
| 기타 | 82 | $120M | $1.5M |

---

### 자금 회수 통계 (2024년)

```
전액 회수: 8% (화이트햇 반환, MEV 봇 오류 등)
부분 회수: 12% (거래소 협력 동결, 협상)
미회수: 80%

회수 성공 사례:
1. Rho Markets: 오라클 오설정 인지 후 공격자 자발 반환
2. Ronin 2차: MEV 봇의 실수, 전액 반환
3. Blueberry: 화이트햇이 선점 후 반환
4. M2 Exchange: 내부 보안팀 빠른 대응으로 전액 회수

회수 실패 주요 원인:
- Tornado Cash/믹서로 세탁 (40%)
- 북한/제재 대상 해커 (30%)
- 신속한 거래소 현금화 (20%)
- 기타 (10%)
```

---

### 국가별 해킹 귀속 (2024-2025)

| 귀속 | 손실액 | 주요 사고 |
|------|--------|---------|
| 북한 Lazarus Group | $1.8B+ | Bybit, WazirX, Radiant, DMM |
| 기타 국가 행위자 | $200M | - |
| 개인/범죄 조직 | $800M | Euler, Mango, Orbit |
| 내부자 | $150M | Munchables, Infini |
| 알 수 없음 | $300M | - |

---

## Part 5: 도구 모음

### 온체인 분석

**Tenderly**
- URL: https://tenderly.co
- 트랜잭션 시뮬레이션, 디버거, 포크 환경, 알림

**Phalcon (BlockSec)**
- URL: https://explorer.phalcon.xyz
- 함수 호출 트리, 자금 흐름 시각화, 공격 재현

**Metadock (MetaSleuth)**
- 주소 라벨링, 자금 흐름 그래프
- URL: https://metasleuth.io

### 정적 분석

```bash
# Slither
pip install slither-analyzer
slither . --detect all
slither . --detect reentrancy-eth,price-manipulation

# Mythril
pip install mythril
myth analyze src/Contract.sol --execution-timeout 120

# Aderyn
cargo install aderyn
aderyn .

# Semgrep
semgrep --config p/smart-contracts src/
```

### 퍼징

```solidity
// Foundry Invariant Fuzz
contract VaultInvariantTest is Test {
    Vault vault;
    address[] actors;

    function invariant_totalAssetsGteTotalShares() external {
        // 자산 >= 주식 (항상)
        assertGe(
            vault.totalAssets(),
            vault.totalSupply(),
            "Assets < Shares invariant violated"
        );
    }

    function invariant_noFreeMoneyForActors() external {
        uint256 totalWithdrawable;
        for (uint i = 0; i < actors.length; i++) {
            totalWithdrawable += vault.maxWithdraw(actors[i]);
        }
        assertLe(totalWithdrawable, vault.totalAssets(), "Free money found");
    }
}
```

```bash
# Echidna
echidna . --contract TestContract --config echidna.yaml

# Medusa
medusa fuzz --target src/ --test-limit 1000000
```

---

## Part 6: 보고서 작성 고급 가이드

### 취약점 심각도 분류

| 등급 | 조건 | 예시 |
|------|-----|-----|
| Critical | 즉각적 자금 손실, 접근 제어 완전 우회 | 재진입으로 전체 풀 탈취 |
| High | 상당한 자금 손실, 주요 기능 파괴 | 오라클 조작으로 과담보 대출 |
| Medium | 제한적 자금 손실, 기능 저하 | 특정 조건에서만 발동 |
| Low | 모범 사례 위반, 미미한 영향 | 이벤트 누락 |
| Informational | 코드 품질 | 주석 오류 |

### PoC 필수 요소

```solidity
/**
 * @title PoC: [취약점 이름]
 * @notice 교육 목적 전용
 *
 * 취약점: [1줄 요약]
 * 영향: [자금 손실 규모 및 범위]
 * 조건: [초기 자본, 특수 권한]
 *
 * 실행:
 * forge test --match-test testExploit --fork-url $ETH_RPC \
 *     --fork-block-number [BLOCK] -vvv
 */
contract ExploitPoC is Test {
    address constant TARGET = 0x...;

    function setUp() external {
        vm.createSelectFork("mainnet", ATTACK_BLOCK - 1);
    }

    function testExploit() external {
        uint256 attackerBalanceBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        // 공격 실행
        vm.stopPrank();

        uint256 profit = token.balanceOf(attacker) - attackerBalanceBefore;
        assertGt(profit, 0, "Exploit failed");
        console2.log("Profit:", profit);
    }
}
```

### 수정 권고안

```diff
// 재진입 버그 수정 (CEI 패턴 적용)
function withdraw(uint256 amount) external {
    require(deposits[msg.sender] >= amount, "Insufficient");
+   deposits[msg.sender] -= amount;  // Effects 먼저
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
-   deposits[msg.sender] -= amount;  // Interactions 이후 상태 변경 제거
}
```

---

*이 가이드는 Web3 보안 생태계의 전체 지형을 제공한다. 버그바운티 플랫폼에 참여하고, 과거 사고를 학습하며, 한국 커뮤니티와 연결하는 것이 전문 보안 연구자로의 빠른 성장 경로다.*
