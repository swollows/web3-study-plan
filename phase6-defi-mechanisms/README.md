# Phase 6: DeFi 프로토콜 메커니즘 보안

> DeFi의 복잡성은 버그를 숨기는 공간을 만든다. 각 프로토콜의 핵심 불변식을 이해하는 것이 보안의 출발점이다.

---

## 목차

1. [AMM 보안](#1-amm-보안)
2. [Lending 프로토콜 보안](#2-lending-프로토콜-보안)
3. [Stablecoin 보안](#3-stablecoin-보안)
4. [Bridge 보안](#4-bridge-보안)
5. [Perpetual DEX 보안](#5-perpetual-dex-보안)
6. [RWA 토큰화 보안](#6-rwa-토큰화-보안)
7. [ERC-4337 EntryPoint 보안](#7-erc-4337-entrypoint-보안)
8. [ERC-7540 비동기 상환 보안](#8-erc-7540-비동기-상환-보안)
9. [크로스 프로토콜 공격 벡터](#9-크로스-프로토콜-공격-벡터)
10. [실전 감사 프레임워크](#10-실전-감사-프레임워크)

---

## 1. AMM 보안

### 1.1 Uniswap V2 보안

#### 핵심 불변식

Constant Product Formula: `x * y = k`

- `x`: 토큰A 보유량
- `y`: 토큰B 보유량
- `k`: 상수 (수수료 제외 스왑 후에도 유지)

수수료 적용 후 실제 검증:

```solidity
// UniswapV2Pair.sol swap() 불변식 검증
uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));
require(
    balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2),
    'UniswapV2: K'
);
```

0.3% 수수료를 포함한 의미: 스왑 후 `k`는 줄어들지 않아야 한다. 수수료가 `k`를 미세하게 증가시킨다.

#### V2 Spot Price Oracle 취약점

`reserve0 / reserve1` 비율을 직접 가격으로 사용하면 Flash Loan으로 단일 트랜잭션 내에서 조작 가능하다.

```solidity
// 취약한 온체인 오라클
contract VulnerableOracle {
    IUniswapV2Pair public pair;

    function getPrice() external view returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0); // 조작 가능!
    }
}
```

**공격 시나리오: Flash Loan + Oracle 조작**

```solidity
contract FlashLoanOracleAttack {
    IUniswapV2Pair public pair;
    IVulnerableLending public lending;
    address public tokenA;
    address public tokenB;

    function attack() external {
        uint256 flashAmount = IERC20(tokenA).balanceOf(address(pair)) * 90 / 100;
        // 플래시론 요청 (콜백으로 uniswapV2Call 호출됨)
        pair.swap(flashAmount, 0, address(this), abi.encode("flash"));
    }

    function uniswapV2Call(
        address,
        uint256 amount0,
        uint256,
        bytes calldata
    ) external {
        // 이 시점: pair의 reserve0 급감, reserve1 급등
        // tokenB 가격이 매우 높게 보임

        // 조작된 가격으로 tokenB 담보 대출
        lending.borrowAgainstCollateral(tokenB, largeAmount);

        // 플래시론 상환 (0.3% 수수료)
        uint256 fee = (amount0 * 3) / 997 + 1;
        IERC20(tokenA).transfer(address(pair), amount0 + fee);

        // 대출금은 그대로 보유 -> 이익
    }
}
```

**방어: TWAP 오라클 구현**

```solidity
contract UniswapV2TWAP {
    IUniswapV2Pair public immutable pair;
    uint32 public blockTimestampLast;
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint224 public price0Average;
    uint224 public price1Average;

    uint32 public constant PERIOD = 30 minutes;

    function update() external {
        (uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) =
            UniswapV2OracleLibrary.currentCumulativePrices(address(pair));

        uint32 timeElapsed = blockTimestamp - blockTimestampLast;
        require(timeElapsed >= PERIOD, 'TWAP: PERIOD_NOT_ELAPSED');

        // 시간 가중 평균 = 누적 가격 차이 / 경과 시간
        price0Average = uint224((price0Cumulative - price0CumulativeLast) / timeElapsed);
        price1Average = uint224((price1Cumulative - price1CumulativeLast) / timeElapsed);

        price0CumulativeLast = price0Cumulative;
        price1CumulativeLast = price1Cumulative;
        blockTimestampLast = blockTimestamp;
    }

    function consult(address token, uint256 amountIn) external view returns (uint256) {
        if (token == token0) {
            return FixedPoint.decode144(FixedPoint.uq112x112(price0Average).mul(amountIn));
        } else {
            return FixedPoint.decode144(FixedPoint.uq112x112(price1Average).mul(amountIn));
        }
    }
}
```

---

### 1.2 Uniswap V3 보안

#### 핵심 불변식: Concentrated Liquidity

V3에서 LP는 가격 범위 `[Pa, Pb]`에 유동성을 집중한다. 범위 내 불변식:

```
x_virtual = x + L / sqrt(Pb)
y_virtual = y + L * sqrt(Pa)
x_virtual * y_virtual = L^2
```

실제 보유량 `x`, `y`는 범위 내에 있을 때만 업데이트된다. 범위를 벗어나면 단일 자산만 보유하게 된다.

#### 비영구적 손실(IL) 증폭

V3의 집중 유동성은 자본 효율을 높이는 대신 IL을 증폭시킨다.

```
V2: ETH 2x 상승 시 IL ≈ 5.72%
V3 (1x~2x 범위): IL ≈ 훨씬 크고, 범위 이탈 시 100% 단일 자산 노출
```

**범위 이탈 공격 시나리오:**

```
1. LP가 [1500, 2500] ETH/USDC 범위에 집중 유동성 공급
2. 공격자가 ETH 가격을 2500 위로 밀어올림
3. LP 포지션 범위 이탈 -> 모두 USDC로 전환됨
4. LP는 ETH 상승 수익 없이 USDC만 보유
5. 공격자가 ETH 매도 -> LP가 고점에 USDC로 물림
```

#### Tick Boundary 정밀도 취약점

V3는 가격을 Tick으로 표현: `tick_i = log_{1.0001}(price)`

Tick 경계 근처에서의 유동성 전환은 정수 반올림 오류를 유발할 수 있다.

```solidity
// Tick 경계 근처에서의 유동성 계산
library LiquidityMath {
    function getLiquidityForAmounts(
        uint160 sqrtRatioX96,
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint256 amount0,
        uint256 amount1
    ) internal pure returns (uint128 liquidity) {
        if (sqrtRatioX96 <= sqrtRatioAX96) {
            // 현재가가 범위 아래: token0만 사용
            liquidity = getLiquidityForAmount0(sqrtRatioAX96, sqrtRatioBX96, amount0);
        } else if (sqrtRatioX96 < sqrtRatioBX96) {
            // 현재가가 범위 내: 두 토큰 모두 사용
            uint128 liquidity0 = getLiquidityForAmount0(sqrtRatioX96, sqrtRatioBX96, amount0);
            uint128 liquidity1 = getLiquidityForAmount1(sqrtRatioAX96, sqrtRatioX96, amount1);
            // min을 사용하는 이유: 하나가 먼저 소진되면 나머지 반환
            liquidity = liquidity0 < liquidity1 ? liquidity0 : liquidity1;
        } else {
            // 현재가가 범위 위: token1만 사용
            liquidity = getLiquidityForAmount1(sqrtRatioAX96, sqrtRatioBX96, amount1);
        }
    }
}

// 취약점: MIN_TICK = -887272, MAX_TICK = 887272 경계에서
// sqrtPrice 오버/언더플로우 가능성
// V3는 sqrtPriceX96 = sqrt(price) * 2^96 형태로 저장
```

---

### 1.3 Uniswap V4 Hooks 보안

#### Hooks 아키텍처 개요

Uniswap V4는 풀 생성 시 "hook" 컨트랙트를 지정할 수 있게 한다. Hook은 스왑, 유동성 추가/제거의 전후에 커스텀 로직을 실행한다.

```
Hook 실행 지점:
beforeInitialize / afterInitialize
beforeAddLiquidity / afterAddLiquidity
beforeRemoveLiquidity / afterRemoveLiquidity
beforeSwap / afterSwap
beforeDonate / afterDonate
```

#### Reentrancy 취약점

```solidity
// 위험한 Hook: 외부 호출 후 풀 상태 변경
contract MaliciousHook is IHooks {
    IPoolManager public poolManager;

    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external override returns (bytes4, int128) {
        // Hook 내에서 다시 스왑 호출 - reentrancy!
        // V4의 PoolManager는 lock 메커니즘으로 방어하나
        // 복잡한 시나리오에서 우회 가능
        poolManager.swap(key, params, hookData); // 재진입!

        return (IHooks.afterSwap.selector, 0);
    }
}

// 안전한 Hook 구현
contract SafeHook is IHooks {
    bool private _inHook;

    modifier noReentrancy() {
        require(!_inHook, "Hook: REENTRANT");
        _inHook = true;
        _;
        _inHook = false;
    }

    function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external override noReentrancy returns (bytes4, int128) {
        // 안전한 로직
        return (IHooks.afterSwap.selector, 0);
    }
}
```

#### 수수료 이중계산: modifyLiquidity callerDelta

V4 `modifyLiquidity`는 두 개의 델타를 반환한다:
- `callerDelta`: LP가 지불/받는 토큰 양
- `feesAccrued`: 누적된 수수료

Hook이 `feesAccrued`를 무시하면 수수료가 영구적으로 잠긴다.

```solidity
// 취약한 Hook: feesAccrued 무시
function afterAddLiquidity(
    address,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata,
    BalanceDelta delta,
    BalanceDelta feesAccrued, // 이것을 무시!
    bytes calldata
) external override returns (bytes4, BalanceDelta) {
    // feesAccrued 처리 없음 -> 수수료 소실
    return (BaseHook.afterAddLiquidity.selector, delta);
}

// 올바른 구현: feesAccrued를 훅 컨트랙트가 수령하거나 LP에게 반환
function afterAddLiquidity(
    address,
    PoolKey calldata key,
    IPoolManager.ModifyLiquidityParams calldata,
    BalanceDelta delta,
    BalanceDelta feesAccrued,
    bytes calldata
) external override returns (bytes4, BalanceDelta) {
    // 옵션 1: Hook이 수수료 수령 (프로토콜 수수료 모델)
    // hookRevenue0 += feesAccrued.amount0();
    // hookRevenue1 += feesAccrued.amount1();

    // 옵션 2: LP에게 반환 (feesAccrued를 hookDelta에 포함)
    BalanceDelta hookDelta = feesAccrued;
    return (BaseHook.afterAddLiquidity.selector, hookDelta);
}
```

#### Hook 주소 권한 비트맵

V4에서 Hook의 권한은 컨트랙트 주소의 최하위 14비트로 인코딩된다. 배포 시 주소를 채굴(mine)해서 원하는 권한을 설정해야 한다.

```solidity
// 권한 비트 레이아웃 (Hooks.sol)
// bit 13: BEFORE_INITIALIZE
// bit 12: AFTER_INITIALIZE
// bit 11: BEFORE_ADD_LIQUIDITY
// bit 10: AFTER_ADD_LIQUIDITY
// bit 9:  BEFORE_REMOVE_LIQUIDITY
// bit 8:  AFTER_REMOVE_LIQUIDITY
// bit 7:  BEFORE_SWAP
// bit 6:  AFTER_SWAP
// bit 5:  BEFORE_DONATE
// bit 4:  AFTER_DONATE
// bit 3:  BEFORE_SWAP_RETURNS_DELTA
// bit 2:  AFTER_SWAP_RETURNS_DELTA
// bit 1:  AFTER_ADD_LIQUIDITY_RETURNS_DELTA
// bit 0:  AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA

// 권한 검증 실패 시 풀 초기화 revert
library HookMiner {
    function find(
        address deployer,
        uint160 flags,
        bytes memory creationCode,
        bytes memory constructorArgs
    ) internal view returns (address hookAddress, bytes32 salt) {
        bytes memory bytecode = abi.encodePacked(creationCode, constructorArgs);
        bytes32 bytecodeHash = keccak256(bytecode);

        for (uint256 i = 0; i < 1000; i++) {
            salt = bytes32(i);
            hookAddress = computeCreate2Address(deployer, salt, bytecodeHash);
            if (uint160(hookAddress) & Hooks.ALL_HOOK_MASK == flags) {
                return (hookAddress, salt);
            }
        }
        revert("HookMiner: COULD_NOT_FIND");
    }
}
```

---

### 1.4 Curve Finance 보안

#### StableSwap 불변식 (A 파라미터)

Curve StableSwap은 Uniswap(xy=k)과 constant sum(x+y=k) 사이를 증폭 계수 `A`로 조절한다.

```
A * n^n * sum(x_i) + D = A * D * n^n + D^(n+1) / (n^n * prod(x_i))
```

- `A` 높음 → constant sum에 가까움 → 낮은 슬리피지 (스테이블 상황)
- `A` 낮음 → constant product에 가까움 → 높은 슬리피지

`A` 값은 거버넌스로 변경 가능하며, 변경 시 `ramp_A` 함수로 서서히 전환된다. **갑작스러운 A 변경은 풀 가격 왜곡을 일으킬 수 있다.**

```python
# Vyper: ramp_A 로직
@external
def ramp_A(_future_A: uint256, _future_time: uint256):
    assert msg.sender == self.owner
    assert block.timestamp >= self.initial_A_time + MIN_RAMP_TIME
    assert _future_time >= block.timestamp + MIN_RAMP_TIME

    _initial_A: uint256 = self._A()
    assert _future_A > 0 and _future_A < MAX_A
    # A는 최대 10배까지만 변경 가능
    assert ((_future_A >= _initial_A and _future_A <= _initial_A * MAX_A_CHANGE) or
            (_future_A < _initial_A and _future_A * MAX_A_CHANGE >= _initial_A))

    self.initial_A = _initial_A
    self.future_A = _future_A
    self.initial_A_time = block.timestamp
    self.future_A_time = _future_time
```

#### get_virtual_price Read-Only Reentrancy

`get_virtual_price()`는 `D / totalSupply`를 반환하는 view 함수지만, ETH를 받는 콜백 중에 호출하면 조작된 값을 반환한다.

**공격 흐름:**

```
1. 공격자가 Curve ETH 풀에서 remove_liquidity() 호출
2. 풀이 ETH 전송 -> receive() 콜백 실행
3. 콜백 내에서: Curve 내부 상태 = 반만 업데이트됨
   - LP 토큰은 소각됨 (totalSupply 감소)
   - 하지만 reserve는 아직 업데이트 안됨
4. get_virtual_price() = D / (감소한 totalSupply) -> 값 증가!
5. 이 값을 사용하는 오라클/Lending 프로토콜 조작
```

```solidity
// 실제 공격 패턴 (JPEG'd, Mango Markets 유사)
contract ReadOnlyReentrancyAttack {
    ICurveETHPool public curvePool;
    ILendingProtocol public lending;
    address public curveLPToken;

    receive() external payable {
        // ETH 수신 콜백 내에서 재진입
        // 이 시점에서 get_virtual_price()는 인플레이트된 값 반환
        uint256 manipulatedNAV = curvePool.get_virtual_price();

        // 인플레이트된 LP 토큰 가치로 과담보 대출
        lending.depositCollateral(curveLPToken, lpBalance);
        lending.borrow(USDC, manipulatedNAV * lpBalance / 1e18 * 80 / 100);
    }

    function attack(uint256 lpAmount) external {
        // remove_liquidity_one_coin -> receive() 트리거 -> 재진입
        curvePool.remove_liquidity_one_coin(lpAmount, 0, 0); // 0번 = ETH
    }
}
```

**방어 전략:**

```solidity
// 방법 1: Curve V2 풀의 price_oracle() 사용 (TWAP 기반)
contract SafeCurveOracle {
    ICurveV2Pool public pool;

    function getPrice() external view returns (uint256) {
        // price_oracle()은 조작 저항성 있는 EMA 가격 사용
        return pool.price_oracle();
    }
}

// 방법 2: reentrancy 상태 확인 (claim_admin_fees 활용)
contract CurveReentrancyGuard {
    function assertNotInReentrancy(address curvePool) internal {
        // V2 풀의 경우: withdraw_admin_fees()가 reentrancy guard를 트리거
        // 재진입 상태면 revert됨
        try ICurvePool(curvePool).withdraw_admin_fees() {} catch {
            revert("Curve: REENTRANCY_DETECTED");
        }
    }
}

// 방법 3: 최신 Curve V2 풀은 자체 reentrancy guard 내장
// @nonreentrant("lock") 데코레이터가 올바르게 구현됨 (Vyper 0.3.1+ 이후)
```

#### get_p() 조작 가능성

Curve V2 크립토 풀의 `get_p()`는 내부 EMA 가격 오라클이다. 문서에 "easily manipulable"이라고 명시되어 있으며, 외부 가격 오라클로 사용해서는 안 된다.

```python
@external
@view
def get_p() -> uint256[N_COINS-1]:
    """
    @notice Returns the stored price of the coin at index `k` w.r.t the coin
            at index 0.
    @dev This is not a real-time price. It can be easily manipulated.
         The stored price is NOT the same as the internal oracle price.
    """
    price_scale: uint256[N_COINS-1] = self.price_scale
    return price_scale
```

#### Vyper 컴파일러 재진입 잠금 결함 (2023년 7월)

Vyper 0.2.15, 0.2.16, 0.3.0 버전에서 `@nonreentrant` 데코레이터의 스토리지 슬롯 할당 버그가 발견되었다. 특정 조건에서 재진입 잠금이 올바르게 적용되지 않았다.

**영향 받은 풀:**

| 풀 | 손실액 |
|---|---|
| Alchemix alETH-ETH | $13.6M |
| JPEG'd pETH-ETH | $11.4M |
| Metronome msETH-ETH | $3.4M |
| deBridge | ~$0 (화이트햇 선점) |
| CRV/ETH 풀 | $71M (공격 시도, 부분 실패) |

**총 피해:** ~$70M

```vyper
# 취약한 버전의 @nonreentrant 동작
# 동일 함수에서 @nonreentrant("lock")을 두 번 사용하거나
# 특정 컴파일 순서에서 슬롯이 겹치는 문제

@nonreentrant("lock")
@external
def remove_liquidity_one_coin(
    _token_amount: uint256,
    i: int128,
    _min_amount: uint256,
) -> uint256:
    # 0.2.15/0.2.16/0.3.0에서 이 잠금이 무력화됨
    # ETH 전송 후 재진입 가능
    ...
```

**방어:**
- Vyper 0.3.1 이상으로 업그레이드
- 배포 전 컴파일러 버전 확인
- 독립적인 재진입 방지 로직 추가

---

## 2. Lending 프로토콜 보안

### 2.1 핵심 불변식

대출 프로토콜의 핵심 불변식:

```
항상 성립해야 함:
1. totalBorrows <= totalSupply * utilizationRate_max
2. 각 사용자의 healthFactor > 1.0 (청산 불필요 상태)
3. collateralValue * LT >= debtValue
4. protocolReserves >= badDebt
```

### 2.2 Compound V3 (Comet) 청산 메커니즘

```solidity
// Comet.sol 핵심 청산 로직
function absorb(address absorber, address[] calldata accounts) external {
    // 청산자(absorber)가 부실 계정의 부채를 프로토콜이 흡수
    for (uint i = 0; i < accounts.length; i++) {
        address account = accounts[i];
        require(isLiquidatable(account), "Comet: NOT_UNDERWATER");

        AbsorbAssetInfo[] memory assetInfos = quoteAbsorb(account);

        // 부채 소각
        uint256 owed = presentValue(userBasic[account].principal);
        liquidatorPoints[absorber].numAbsorbs++;
        liquidatorPoints[absorber].numAbsorbed += safe64(accounts.length);

        // 담보 프로토콜로 귀속
        for (uint j = 0; j < assetInfos.length; j++) {
            totalsCollateral[assetInfos[j].asset].totalSupplyAsset -= assetInfos[j].seizeAmount;
            userCollateral[account][assetInfos[j].asset].balance -= assetInfos[j].seizeAmount;
            totalsCollateral[assetInfos[j].asset].totalSupplyAsset += assetInfos[j].seizeAmount;
            // ... 프로토콜 자산 증가
        }
    }
}

// 청산 가능 여부 확인
function isLiquidatable(address account) public view returns (bool) {
    int104 principal = userBasic[account].principal;
    if (principal >= 0) return false; // 부채 없으면 청산 불가

    uint256 borrowAmount = presentValue(uint104(-principal));
    uint256 borrowCapacity = getBorrowCapacityForAccount(account); // 담보 * 청산임계값

    return borrowCapacity < borrowAmount;
}
```

### 2.3 Oracle 의존성과 가격 조작

**취약한 오라클 패턴들:**

```solidity
// 패턴 1: Spot Price 직접 사용 (최악)
function getPrice_BAD(address token) external view returns (uint256) {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
    return r1 * 1e18 / r0; // Flash Loan으로 단일 TX에서 조작 가능
}

// 패턴 2: 단일 Chainlink 피드 (중간 - staleness 미확인)
function getPrice_MEDIUM(address token) external view returns (uint256) {
    (, int256 price,,,) = AggregatorV3Interface(feed).latestRoundData();
    return uint256(price); // staleness 미확인, 음수 확인 없음
}

// 패턴 3: 안전한 Chainlink 구현
function getPrice_SAFE(address token) external view returns (uint256) {
    AggregatorV3Interface feed = priceFeeds[token];
    (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = feed.latestRoundData();

    // 1. 신선도 확인
    require(
        updatedAt >= block.timestamp - MAX_STALENESS[token],
        "Oracle: STALE_PRICE"
    );
    // 2. 음수 확인
    require(answer > 0, "Oracle: NEGATIVE_PRICE");
    // 3. 라운드 완료 확인
    require(answeredInRound >= roundId, "Oracle: INCOMPLETE_ROUND");
    // 4. 시작 시간 확인 (phase 변경 감지)
    require(startedAt > 0, "Oracle: ROUND_NOT_STARTED");

    return uint256(answer);
}
```

### 2.4 Flash Loan + Oracle 복합 공격

**실제 공격 재현 (Mango Markets 스타일, 2022년 10월 $116M):**

```
공격 순서:
1. 두 개의 계정 준비 (Acc_A, Acc_B)
2. Acc_A: MNGO 현물 대량 구매 (가격 펌핑)
3. Acc_B: MNGO 현물 대량 구매 (동시)
4. MNGO 가격 $0.03 → $0.91 (30배 펌핑)
5. Acc_A: 펌핑된 MNGO를 담보로 모든 자산 대출
6. Acc_B: 포지션으로 이익 실현
7. Acc_A: 대출금 상환 없이 퇴장 (나쁜 부채 $116M 남김)
8. Governance 통해 추가 자금 탈취 시도
```

```solidity
// 온체인 가격 오라클을 사용하는 프로토콜의 취약점
contract MangoStyleVulnerable {
    // MNGO/USDC 스팟 DEX 가격을 직접 사용
    ISpotOracle public oracle;

    function getAccountLiquidity(address account)
        public view returns (uint256 collateralValue, uint256 debtValue) {

        for (uint i = 0; i < positions[account].length; i++) {
            address token = positions[account][i].token;
            uint256 price = oracle.getSpotPrice(token); // 조작 가능!
            collateralValue += positions[account][i].amount * price;
        }
        // ...
    }
}
```

### 2.5 Interest Rate Model 취약점

```solidity
// Compound의 Jump Rate Model
contract JumpRateModelV2 {
    uint256 public multiplierPerBlock;
    uint256 public baseRatePerBlock;
    uint256 public jumpMultiplierPerBlock;
    uint256 public kink; // 일반적으로 80%

    function getBorrowRate(
        uint256 cash,
        uint256 borrows,
        uint256 reserves
    ) public view override returns (uint256) {
        uint256 util = utilizationRate(cash, borrows, reserves);

        if (util <= kink) {
            return util * multiplierPerBlock / 1e18 + baseRatePerBlock;
        } else {
            uint256 normalRate = kink * multiplierPerBlock / 1e18 + baseRatePerBlock;
            uint256 excessUtil = util - kink;
            // kink 초과 시 jumpMultiplierPerBlock 적용
            return excessUtil * jumpMultiplierPerBlock / 1e18 + normalRate;
        }
    }

    // 취약점 시나리오:
    // jumpMultiplier가 과도하게 높게 설정된 경우
    // 활용률 80% → 90%로 변화 시 이자율이 수천% 상승
    // → 기존 차입자 청산 캐스케이드
    // → 청산 봇 gas 경쟁 → gas 폭등 → 청산 실패 → Bad Debt
}
```

### 2.6 Bad Debt 시나리오와 방어

```
Black Thursday (2020.03.12) 분석:
1. ETH: $190 → $90 (-52%) in 24시간
2. MakerDAO CDP 청산 트리거
3. Gas: 10 gwei → 200 gwei (청산 봇 경쟁)
4. 일부 청산 봇: gas 부족으로 TX 실패
5. 악의적 참여자: 0 DAI 입찰로 $8.32M 담보 취득
6. MakerDAO: 4만 MKR 발행하여 경매, $5.4M 충당

방어 전략:
- 청산 임계값 보수적으로 설정 (150%+)
- 다중 청산 봇 인센티브
- Bad Debt 보험 기금 (Insurance Fund)
- 서킷 브레이커: 급락 시 청산 일시 중단
```

---

## 3. Stablecoin 보안

### 3.1 스테이블코인 트릴레마

```
     탈중앙화
      /    \
     /      \
    /        \
안정성 ---- 자본효율성

- USDT/USDC: 중앙화 + 안정 + 효율 (탈중앙화 X)
- DAI (V1): 탈중앙화 + 안정 + 비효율 (150%+ 담보)
- UST: 탈중앙화 + (불안정) + 효율 -> 붕괴
- FRAX: 부분 담보 하이브리드 (트릴레마 완화 시도)
```

### 3.2 알고리즘 스테이블코인: Terra/Luna 붕괴 분석

**메커니즘:**

```
UST 발행: LUNA $1 어치 소각 → UST 1개 발행
UST 상환: UST 1개 소각 → LUNA $1 어치 발행

이론적 페그 유지:
- UST < $1: 차익거래자가 $0.99 UST 구매 → LUNA $1로 교환 → $0.01 이익
- UST > $1: 차익거래자가 LUNA $1 구매 → UST $1.01로 교환 → $0.01 이익
```

**붕괴 메커니즘 (2022년 5월, $40B 손실):**

```
Day 1:
- $285M UST가 Curve 풀에서 대규모 매도 (공격자 or 패닉)
- UST 페그: $1.00 → $0.98
- Anchor Protocol에서 UST 인출 시작

Day 2:
- 차익거래자들: UST 매수 → LUNA 교환 (LUNA 공급 급증)
- LUNA 가격: $80 → $30 (-62%)
- LUNA 가치 하락 → UST 1달러 상환에 더 많은 LUNA 필요
- 더 많은 LUNA 발행 → LUNA 가격 추가 하락

Day 3-5: 죽음의 소용돌이
- LUNA 발행량: 3.5억 개 → 6.5조 개 (18,000배 증가)
- LUNA 가격: $0.0001 수준으로 폭락
- UST: $0.10 이하
- 총 시가총액 $40B 소멸
```

**코드 레벨 취약점:**

```solidity
// 알고리즘 스테이블코인의 근본 취약점 패턴
contract AlgoStablecoin {
    IERC20 public stablecoin; // UST
    IERC20 public govToken;   // LUNA

    // 무한 발행 가능 - 패닉 시 govToken 희석 불가피
    function redeemStable(uint256 stableAmount) external {
        uint256 govAmount = stableAmount * 1e18 / getGovTokenPrice();

        stablecoin.burnFrom(msg.sender, stableAmount);
        govToken.mint(msg.sender, govAmount); // 공급량 제한 없음!
    }

    // govToken 가격이 하락하면 같은 USD 가치에 더 많은 govToken 발행
    // → 가격 추가 하락 → 무한 루프
    function getGovTokenPrice() public view returns (uint256) {
        return oracle.getPrice(address(govToken)); // 실시간 가격 사용
    }
}
```

### 3.3 CDP 기반 스테이블코인 (MakerDAO/DAI)

```solidity
// MakerDAO Vat.sol 핵심 불변식
contract Vat {
    // 전체 DAI = 전체 담보 * 해당 담보 가격 / 부채 비율
    // 항상: sum(dart * rate) <= sum(ink * spot)

    // ink: 담보량, art: 정규화된 부채, spot: 청산 가격
    // rate: 누적 이자율, dart: 부채 변화량

    function frob(
        bytes32 ilk,   // 담보 유형 (ETH-A, WBTC-A 등)
        address u,     // 담보 제공자
        address v,     // USDC 수령자
        address w,     // DAI 수령자
        int256 dink,   // 담보 변화량
        int256 dart    // 부채 변화량
    ) external {
        Urn memory urn = urns[ilk][u];
        Ilk memory ilk_ = ilks[ilk];

        urn.ink = _add(urn.ink, dink);
        urn.art = _add(urn.art, dart);
        ilk_.Art = _add(ilk_.Art, dart);

        int256 dtab = _mul(ilk_.rate, dart);
        uint256 tab = _mul(ilk_.rate, urn.art);

        // 핵심 불변식 검사
        require(
            urn.art == 0 ||              // 부채 없거나
            tab <= _mul(urn.ink, ilk_.spot), // 담보가 충분하거나
            "Vat/not-safe"
        );
    }
}
```

**PSM (Peg Stability Module) 보안:**

```solidity
// DAI <-> USDC 1:1 교환 모듈
// 취약점: USDC 블랙리스트 가능성, 중앙화 리스크

contract DssPsm {
    GemJoin public immutable gemJoin;
    uint256 public tin;  // 입금 수수료 (bps)
    uint256 public tout; // 출금 수수료 (bps)

    function sellGem(address usr, uint256 gemAmt) external {
        uint256 gemAmt18 = gemAmt * (10 ** (18 - gem.decimals()));
        uint256 daiAmt = gemAmt18 - gemAmt18 * tin / WAD;

        gemJoin.join(address(this), gemAmt);
        vat.frob(ilk, address(this), address(this), address(this),
                 int256(gemAmt18), int256(gemAmt18));
        vat.move(address(this), usr, daiAmt * RAY);
        daiJoin.exit(usr, daiAmt);
    }

    // 취약점: USDC가 블랙리스트 처리되면 PSM 자금 동결
    // MakerDAO는 실제로 USDC 집중화 리스크를 가지고 있음 (2023년 기준 30%+ 담보)
}
```

---

## 4. Bridge 보안

### 4.1 Lock-and-Mint 아키텍처

```
Source Chain (Ethereum)        Destination Chain (BSC)
        |                               |
   Lock ETH in vault              Mint wETH
        |                               |
   Emit event/message    →   Validator confirms
        |                               |
   (waiting)               Release/mint to user
```

**핵심 보안 요소:**
1. 메시지 인증 (누가 발행을 승인하는가)
2. 이중 지출 방지 (동일 메시지 재처리 방지)
3. 운영자 탈취 방지 (검증자 키 보안)

### 4.2 메시지 검증 취약점

**Wormhole 해킹 ($320M, 2022년 2월):**

```
취약점: Solana 프로그램에서 서명 검증 로직 결함
- verify_signatures() 함수가 System Program을 불신뢰하게 호출
- 공격자가 가짜 서명 검증 어카운트 생성
- 실제 Guardian 서명 없이 메시지 인증 통과
- 12만 ETH 발행 (Ethereum 측)
```

```rust
// 취약한 Solana 프로그램 패턴 (의사코드)
pub fn post_vaa(ctx: Context<PostVAA>, vaa: Vec<u8>) -> ProgramResult {
    let sig_info = &ctx.accounts.signature_set;

    // 취약점: sig_info의 소유권을 검증하지 않음
    // 공격자가 자신이 만든 sig_info 계정 전달 가능
    if sig_info.num_valid_signatures < QUORUM {
        return Err(WormholeError::InvalidSignatures.into());
    }

    // 서명이 유효하다고 가정하고 메시지 처리
    process_message(ctx, vaa)?;
    Ok(())
}
```

**Ronin Bridge 해킹 ($625M, 2022년 3월):**

```
구조: 9개 검증자, 5/9 다중서명 필요
공격:
1. 사회공학(Spear Phishing)으로 Sky Mavis 엔지니어 침해
2. Sky Mavis 보유 4개 검증자 키 탈취
3. Axie DAO 검증자 노드 (gas-free RPC 통해 접근) 키 탈취
4. 5/9 서명 달성
5. 2개 트랜잭션으로 ETH 173,600개 + USDC 25.5M 탈취

교훈:
- 검증자 키 분산 저장 필수
- HSM(Hardware Security Module) 사용
- 다중 서명자는 물리적으로 분리된 위치에 있어야
- gas-free RPC 등 편의 기능이 보안 허점
```

**Nomad Bridge ($190M, 2022년 8월):**

```
취약점: 메시지 루트 초기화 버그
- 루트를 0x00...0으로 초기화 (신뢰할 수 없는 기본값)
- process() 함수에서 proved[root][leaf]를 확인
- 0x00...0이 기본적으로 true (매핑 기본값)
- 누구나 임의 메시지를 "증명된 것처럼" 처리 가능
- 커뮤니티 대규모 복사 공격 발생 (모두가 같은 페이로드 복사)
```

```solidity
// Nomad 취약한 패턴 (의사코드)
function process(bytes memory message) public returns (bool success) {
    bytes32 messageHash = keccak256(message);

    // 취약점: acceptableRoot()가 0x00...0을 허용
    require(acceptableRoot(messages[messageHash]), "!proven");

    // 모든 메시지가 기본값으로 "이미 증명됨" 처리
    // ...
}

mapping(bytes32 => uint256) public confirmAt;

function acceptableRoot(bytes32 root) public view returns (bool) {
    uint256 time = confirmAt[root];
    // 취약점: time == 0이면 block.timestamp >= 0 + 0 = true
    return time != 0 && block.timestamp >= time;
    // 원래는: return time != 0 && block.timestamp >= time;
    // 실제 배포된 버그: return block.timestamp >= time; (time=0 허용)
}
```

### 4.3 Finality 가정 리스크

```solidity
// 체인별 finality 시간
// Ethereum: ~12분 (2 epoch = 64 blocks)
// Bitcoin: ~60분 (6 blocks)
// Solana: ~400ms (최종화)
// Polygon: ~256 blocks (재조직 위험)

contract FinalityAwareBridge {
    mapping(uint256 => uint256) public requiredConfirmations;

    constructor() {
        requiredConfirmations[1] = 20;    // Ethereum: 20 blocks
        requiredConfirmations[56] = 30;   // BSC: 30 blocks
        requiredConfirmations[137] = 256; // Polygon: 256 blocks (재조직 위험)
    }

    function processDeposit(
        uint256 sourceChain,
        uint256 depositBlock,
        bytes calldata proof
    ) external {
        require(
            block.number >= depositBlock + requiredConfirmations[sourceChain],
            "Bridge: INSUFFICIENT_FINALITY"
        );
        // ...
    }
}
```

### 4.4 업그레이드 메커니즘 취약점

```solidity
// ProxyAdmin을 통한 브리지 컨트랙트 업그레이드
// 취약점: timelock 없이 즉시 업그레이드 가능

contract VulnerableBridgeProxy {
    address public implementation;
    address public admin;

    function upgrade(address newImpl) external {
        require(msg.sender == admin, "Not admin");
        // timelock 없음! 즉시 악성 구현으로 교체 가능
        implementation = newImpl;
    }
}

// 안전한 패턴: 2단계 + Timelock
contract SecureBridgeProxy {
    address public pendingImplementation;
    uint256 public upgradeTimestamp;
    uint256 public constant UPGRADE_DELAY = 2 days;

    function proposeUpgrade(address newImpl) external onlyMultisig {
        pendingImplementation = newImpl;
        upgradeTimestamp = block.timestamp + UPGRADE_DELAY;
        emit UpgradeProposed(newImpl, upgradeTimestamp);
    }

    function executeUpgrade() external onlyMultisig {
        require(block.timestamp >= upgradeTimestamp, "Timelock active");
        require(pendingImplementation != address(0), "No pending upgrade");
        implementation = pendingImplementation;
        pendingImplementation = address(0);
    }
}
```

---

## 5. Perpetual DEX 보안

### 5.1 Oracle 모델 비교

```
CEX 기반 오라클 (GMX V1):
- Chainlink + 자체 가격 집계
- 장점: 조작 어려움
- 단점: Toxic flow (지연 정보 활용)

AMM 기반 (dYdX V3):
- 자체 온체인 주문서
- 장점: 가격 발견 공정
- 단점: 유동성 의존

하이브리드 (Synthetix V3):
- Pyth Network + Chainlink
- 장점: 빠른 업데이트
- 단점: 오라클 신뢰 의존
```

### 5.2 Oracle Toxic Flow 공격

```
GMX V1 Toxic Flow 시나리오:
1. 공격자가 저유동성 CEX에서 ALT 코인 가격 펌핑
2. GMX 오라클이 CEX 가격을 반영하기까지 지연 발생
3. 공격자가 펌핑 직전 GMX에서 ALT Long 포지션 오픈
4. 오라클 업데이트 후 PnL 실현
5. GLP 유동성 제공자들이 피해

실제 사례:
- AVAX 가격 조작으로 ~$600K 손실 (2022년)
- 대응: GMX V2는 Chainlink Low Latency Feed 도입
```

```solidity
// GMX V2의 개선된 오라클 검증
contract GMXOracleVerifier {
    // Low Latency Feed: 실시간 서명된 가격 데이터
    struct PricePackage {
        bytes32 feedId;
        uint256 observationsTimestamp;
        int192 median;
        int192 bid;
        int192 ask;
        bytes32 blockHash;
        uint256 blockNumber;
        bytes signature;
    }

    function verifyAndGetPrice(PricePackage calldata pkg) external view returns (int256) {
        // 블록 해시 검증 (해당 블록에서 실제로 관찰된 가격인지)
        require(
            blockhash(pkg.blockNumber) == pkg.blockHash ||
            block.number - pkg.blockNumber > 256, // 256블록 이상 지난 경우 허용
            "Oracle: INVALID_BLOCK_HASH"
        );

        // 서명 검증
        bytes32 messageHash = keccak256(abi.encode(
            pkg.feedId, pkg.observationsTimestamp, pkg.median, pkg.blockHash
        ));
        require(
            ECDSA.recover(messageHash, pkg.signature) == trustedSigner,
            "Oracle: INVALID_SIGNATURE"
        );

        return pkg.median;
    }
}
```

### 5.3 Funding Rate 조작

```solidity
// Perpetual DEX Funding Rate 메커니즘
contract PerpFundingRate {
    int256 public constant MAX_FUNDING_RATE = 0.05e18; // 8시간당 5% 최대

    struct Market {
        uint256 longOpenInterest;
        uint256 shortOpenInterest;
        int256 cumulativeFundingRate;
        uint256 lastFundingTime;
    }

    function calculateFundingRate(Market memory market) public pure returns (int256) {
        if (market.longOpenInterest == 0 && market.shortOpenInterest == 0) {
            return 0;
        }

        // Premium = (Long OI - Short OI) / (Long OI + Short OI)
        int256 longOI = int256(market.longOpenInterest);
        int256 shortOI = int256(market.shortOpenInterest);
        int256 totalOI = longOI + shortOI;

        int256 premium = (longOI - shortOI) * 1e18 / totalOI;

        // Clamp to [-5%, 5%]
        if (premium > MAX_FUNDING_RATE) return MAX_FUNDING_RATE;
        if (premium < -MAX_FUNDING_RATE) return -MAX_FUNDING_RATE;
        return premium;
    }

    // 취약점: 공격자가 OI를 한쪽으로 치우치게 해서
    // 반대 포지션 보유자들에게 높은 funding rate 부과
    // → 강제 청산 유도
}
```

---

## 6. RWA 토큰화 보안

### 6.1 구조적 리스크

```
온체인 토큰
    ↑ (오라클)
SPV/Trust 계약 (법적 래퍼)
    ↑
실물 자산 (부동산, 채권, 인보이스)

리스크 레이어:
1. Smart Contract 리스크 (온체인 버그)
2. Oracle 리스크 (자산 평가 조작)
3. Legal 리스크 (법적 집행 불가능성)
4. Custodian 리스크 (수탁인 부실)
5. Regulatory 리스크 (규제 변화)
```

### 6.2 Off-chain Legal Wrapper 취약점

```
시나리오: 부동산 RWA 토큰
1. Delaware LLC가 부동산 소유
2. LLC 지분을 ERC-20 토큰으로 표현
3. 토큰 보유자가 청산 요청

문제점:
- 스마트 컨트랙트로 LLC 청산 강제 불가
- 관할권별 법 다름 (미국 LLC vs 한국 토큰 보유자)
- 토큰 소각 = 실물 자산 양도 아님
- 온체인 이전과 법적 소유권 불일치 가능
```

```solidity
// ERC-1400 보안 토큰 구현 (허가 기반)
contract RWAToken is ERC1400 {
    IComplianceEngine public complianceEngine;

    function transferWithData(
        address from,
        address to,
        uint256 value,
        bytes calldata data
    ) external override {
        // 규정 준수 확인
        (bool canTransfer, byte statusCode, bytes32 appCode) =
            complianceEngine.canTransfer(from, to, value, data);

        require(canTransfer, string(abi.encodePacked(statusCode)));

        _transfer(from, to, value);
    }

    // 강제 이전 (법원 명령 등)
    function controllerTransfer(
        address from,
        address to,
        uint256 value,
        bytes calldata data,
        bytes calldata operatorData
    ) external onlyController {
        _transfer(from, to, value);
        emit ControllerTransfer(msg.sender, from, to, value, data, operatorData);
    }

    // 취약점: controller 키 탈취 시 임의 이전 가능
    // 방어: 다중서명 + 타임락 + 온체인 거버넌스
}
```

### 6.3 Burn-and-Remint Recovery

```solidity
// RWA 토큰 복구 메커니즘
contract RWARecoveryAgent {
    address public recoveryAgentMultisig;
    uint256 public constant RECOVERY_TIMELOCK = 48 hours;

    struct RecoveryRequest {
        address wrongHolder;
        address correctHolder;
        uint256 amount;
        uint256 requestedAt;
        bool executed;
        uint256 approvalCount;
        mapping(address => bool) approved;
    }

    mapping(uint256 => RecoveryRequest) public requests;
    uint256 public requestCount;

    function proposeRecovery(
        address wrongHolder,
        address correctHolder,
        uint256 amount,
        bytes calldata legalProof
    ) external onlyRecoveryAgent returns (uint256 requestId) {
        requestId = requestCount++;
        RecoveryRequest storage req = requests[requestId];
        req.wrongHolder = wrongHolder;
        req.correctHolder = correctHolder;
        req.amount = amount;
        req.requestedAt = block.timestamp;
        emit RecoveryProposed(requestId, wrongHolder, correctHolder, amount, legalProof);
    }

    function executeRecovery(uint256 requestId) external onlyRecoveryAgent {
        RecoveryRequest storage req = requests[requestId];
        require(!req.executed, "Already executed");
        require(block.timestamp >= req.requestedAt + RECOVERY_TIMELOCK, "Timelock");
        require(req.approvalCount >= 3, "Insufficient approvals"); // 3/5 다중서명

        req.executed = true;
        token.forceBurn(req.wrongHolder, req.amount);
        token.forceMint(req.correctHolder, req.amount);
    }
}
```

---

## 7. ERC-4337 EntryPoint 보안

### 7.1 아키텍처 개요

```
사용자
  ↓ (UserOperation)
Bundler (트랜잭션 번들러)
  ↓ (handleOps 호출)
EntryPoint (싱글톤)
  ↓
Account Contract (개별 지갑)
  ↓
Target Contract (실제 실행)

+ Paymaster (가스비 대납 옵션)
```

### 7.2 싱글톤 신뢰 집중 문제

EntryPoint는 모든 AA 지갑이 신뢰하는 싱글톤이다. 버그 발생 시 전체 생태계 영향.

```solidity
// EntryPoint v0.6 핵심 구조
contract EntryPoint is IEntryPoint {
    // 싱글톤 - 모든 AA 지갑이 이 컨트랙트를 신뢰

    function handleOps(
        UserOperation[] calldata ops,
        address payable beneficiary
    ) public {
        uint256 opslen = ops.length;
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        // Phase 1: 검증
        for (uint256 i = 0; i < opslen; i++) {
            _validatePrepayment(i, ops[i], opInfos[i]);
        }

        // Phase 2: 실행
        uint256 collected = 0;
        for (uint256 i = 0; i < opslen; i++) {
            collected += _executeUserOp(i, ops[i], opInfos[i]);
        }

        // 번들러에게 가스비 지급
        beneficiary.transfer(collected);
    }

    // 취약점: beneficiary가 신뢰되지 않은 주소라면?
    // → beneficiary.transfer()에서 fallback 실행
    // → 재진입 가능성 (handled by nonReentrant)
}
```

### 7.3 Paymaster 악용 시나리오

```solidity
// 취약한 Paymaster: 무제한 가스 대납
contract VulnerablePaymaster is BasePaymaster {
    // 모든 UserOp를 무조건 후원
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        // 가스 한도 없음! 공격자가 복잡한 연산 무료로 실행 가능
        return ("", 0);
    }
}

// 공격 시나리오
contract PaymasterDrainer {
    function attack(IEntryPoint entryPoint, address paymaster) external {
        // Paymaster 잔액이 소진될 때까지 반복
        UserOperation memory op = UserOperation({
            sender: address(this),
            nonce: getNextNonce(),
            initCode: "",
            callData: abi.encodeWithSignature("expensiveLoop()"),
            callGasLimit: 10_000_000,  // 최대 가스 요청
            verificationGasLimit: 100_000,
            preVerificationGas: 21_000,
            maxFeePerGas: 1 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: abi.encodePacked(paymaster),
            signature: ""
        });

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, payable(msg.sender));
    }
}

// 안전한 Paymaster
contract SafePaymaster is BasePaymaster {
    mapping(address => uint256) public lastSponsoredBlock;
    mapping(address => uint256) public dailySpending;
    uint256 public constant MAX_GAS_PER_OP = 500_000;
    uint256 public constant DAILY_LIMIT = 0.01 ether;

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        // 1. 가스 한도 검증
        require(
            userOp.callGasLimit + userOp.verificationGasLimit <= MAX_GAS_PER_OP,
            "Paymaster: GAS_TOO_HIGH"
        );

        // 2. 일일 한도 검증
        uint256 today = block.timestamp / 1 days;
        if (lastSponsoredBlock[userOp.sender] / 1 days < today) {
            dailySpending[userOp.sender] = 0; // 일일 초기화
        }
        require(
            dailySpending[userOp.sender] + maxCost <= DAILY_LIMIT,
            "Paymaster: DAILY_LIMIT_EXCEEDED"
        );

        dailySpending[userOp.sender] += maxCost;
        lastSponsoredBlock[userOp.sender] = block.number;

        return (abi.encode(userOp.sender, maxCost), 0);
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external override {
        if (mode == PostOpMode.opReverted) {
            // 실패한 경우 spending 복원 (선택적)
            (address sender, uint256 maxCost) = abi.decode(context, (address, uint256));
            dailySpending[sender] -= maxCost - actualGasCost;
        }
    }
}
```

### 7.4 UserOperation 서명 재생 방지

```solidity
// 올바른 nonce 관리
contract SecureAAWallet {
    IEntryPoint public immutable entryPoint;
    address public owner;

    // 2D nonce: key (상위 192비트) + sequence (하위 64비트)
    // 병렬 트랜잭션 지원을 위한 nonce key

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        // EntryPoint만 호출 가능
        require(msg.sender == address(entryPoint), "AA: NOT_ENTRYPOINT");

        // nonce는 EntryPoint가 관리 (2D nonce 지원)
        // 서명 검증
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address recovered = hash.recover(userOp.signature);

        if (recovered != owner) {
            return SIG_VALIDATION_FAILED; // 1
        }

        // 가스비 부족분 선납
        if (missingAccountFunds > 0) {
            payable(msg.sender).call{value: missingAccountFunds}("");
        }

        return 0; // 성공
    }

    // chainId를 서명에 포함시켜 크로스체인 재생 방지
    function encodeUserOpHash(UserOperation calldata op) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256(abi.encode(
                op.sender, op.nonce, keccak256(op.initCode),
                keccak256(op.callData), op.callGasLimit,
                op.verificationGasLimit, op.preVerificationGas,
                op.maxFeePerGas, op.maxPriorityFeePerGas,
                keccak256(op.paymasterAndData)
            )),
            address(entryPoint),
            block.chainid  // chainId 포함!
        ));
    }
}
```

---

## 8. ERC-7540 비동기 상환 보안

### 8.1 핵심 불변식

ERC-7540 (Async Tokenized Vaults):

```
언제나 성립:
1. pendingRedeemRequest + claimableRedeemRequest <= totalPendingShares
2. claimableAssets >= 처리된 모든 상환 요청의 자산 총량
3. 이미 처리된 requestId는 재처리 불가
4. epoch 상환 한도 초과 불가
```

### 8.2 비동기 상환 Bank-Run 방지

```solidity
contract ERC7540Vault is ERC4626, IERC7540 {
    uint256 public epochDuration;
    uint256 public maxRedeemPerEpoch;
    uint256 public currentEpochStart;
    uint256 public currentEpochRedemptions;

    mapping(uint256 => RedemptionRequest) public redeemRequests;
    mapping(address => uint256[]) public userRequestIds;
    uint256 private _nextRequestId;

    struct RedemptionRequest {
        address controller;
        address owner;
        uint256 shares;
        uint256 requestedAt;
        bool fulfilled;
        bool cancelled;
    }

    function requestRedeem(
        uint256 shares,
        address controller,
        address owner
    ) external returns (uint256 requestId) {
        require(shares > 0, "ERC7540: ZERO_SHARES");
        require(balanceOf(owner) >= shares, "ERC7540: INSUFFICIENT_BALANCE");

        // 에포크 초기화
        _updateEpoch();

        // 에포크 상환 한도 확인 (Bank-run 방지 핵심)
        require(
            currentEpochRedemptions + shares <= maxRedeemPerEpoch,
            "ERC7540: EPOCH_LIMIT"
        );

        currentEpochRedemptions += shares;
        requestId = _nextRequestId++;

        redeemRequests[requestId] = RedemptionRequest({
            controller: controller,
            owner: owner,
            shares: shares,
            requestedAt: block.timestamp,
            fulfilled: false,
            cancelled: false
        });

        userRequestIds[owner].push(requestId);

        // 주식을 금고에 잠금 (이전 불가)
        _transfer(owner, address(this), shares);

        emit RedeemRequest(controller, owner, requestId, msg.sender, shares);
        return requestId;
    }

    function fulfillRedeem(uint256 requestId) external onlyOperator {
        RedemptionRequest storage req = redeemRequests[requestId];
        require(!req.fulfilled && !req.cancelled, "ERC7540: INVALID_STATE");
        require(
            block.timestamp >= req.requestedAt + epochDuration,
            "ERC7540: EPOCH_NOT_COMPLETE"
        );

        req.fulfilled = true;
        uint256 assets = convertToAssets(req.shares);

        _burn(address(this), req.shares);
        IERC20(asset()).safeTransfer(req.controller, assets);

        emit RedeemFulfilled(requestId, req.controller, assets);
    }

    function _updateEpoch() internal {
        if (block.timestamp >= currentEpochStart + epochDuration) {
            currentEpochStart = block.timestamp;
            currentEpochRedemptions = 0;
        }
    }
}
```

### 8.3 NAV Oracle 조작 취약점

```solidity
// 취약한 NAV 계산
contract VulnerableRWAVault is ERC7540Vault {
    ISpotOracle public navOracle; // 조작 가능한 스팟 오라클

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        uint256 nav = navOracle.getNAV(); // 스팟 가격 사용 -> 조작 가능
        return shares * nav / totalSupply();
    }
}

// 안전한 NAV 계산
contract SecureRWAVault is ERC7540Vault {
    IChainlinkAggregator public navOracle;
    uint256 public constant MAX_NAV_STALENESS = 24 hours;
    uint256 public constant MAX_NAV_DEVIATION = 500; // 5%

    uint256 private _lastVerifiedNAV;
    uint256 private _lastVerifiedAt;

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        uint256 nav = _getVerifiedNAV();
        return shares * nav / totalSupply();
    }

    function _getVerifiedNAV() internal view returns (uint256) {
        (, int256 answer,, uint256 updatedAt,) = navOracle.latestRoundData();
        require(updatedAt >= block.timestamp - MAX_NAV_STALENESS, "NAV: STALE");
        require(answer > 0, "NAV: NEGATIVE");

        uint256 newNAV = uint256(answer);

        // 급격한 NAV 변화 감지
        if (_lastVerifiedNAV > 0) {
            uint256 deviation = newNAV > _lastVerifiedNAV
                ? (newNAV - _lastVerifiedNAV) * 10000 / _lastVerifiedNAV
                : (_lastVerifiedNAV - newNAV) * 10000 / _lastVerifiedNAV;

            require(deviation <= MAX_NAV_DEVIATION, "NAV: EXCESSIVE_DEVIATION");
        }

        return newNAV;
    }
}
```

---

## 9. 크로스 프로토콜 공격 벡터

### 9.1 Flash Loan 복합 공격 분류

```
유형 1: Flash Loan + Oracle 조작 + Lending
- Cream Finance ($130M), Mango Markets ($116M)
- 플래시론으로 가격 조작 → 담보 대출

유형 2: Flash Loan + AMM Arbitrage
- 여러 풀 간 가격 차이 이용
- 프로토콜 손실 발생 가능

유형 3: Flash Loan + Governance Attack
- Beanstalk ($182M): 플래시론으로 거버넌스 파워 임시 획득
- 단일 블록에서 제안 + 투표 + 실행

유형 4: Flash Loan + Liquidation Cascade
- 유동성 고갈 → 청산 불가 → Bad Debt
```

### 9.2 거버넌스 공격 방어

```solidity
// 취약한 거버넌스: 스냅샷 없음
contract VulnerableGovernance {
    IERC20 public govToken;

    function getVotingPower(address voter) public view returns (uint256) {
        return govToken.balanceOf(voter); // 현재 잔액 사용 - 플래시론 취약
    }

    function castVote(uint256 proposalId, bool support) external {
        uint256 votes = getVotingPower(msg.sender);
        // 플래시론으로 일시적으로 대량 토큰 보유 → 투표 조작!
        _castVote(proposalId, msg.sender, votes, support);
    }
}

// 안전한 거버넌스: 블록 스냅샷 사용
contract SecureGovernance {
    IVotes public govToken; // EIP-712 투표 토큰

    mapping(uint256 => uint256) public proposalSnapshotBlock;

    function createProposal(...) external returns (uint256 proposalId) {
        proposalId = ...;
        // 현재 블록보다 1 이전 블록 스냅샷 (조작 방지)
        proposalSnapshotBlock[proposalId] = block.number - 1;
    }

    function castVote(uint256 proposalId, bool support) external {
        uint256 snapshot = proposalSnapshotBlock[proposalId];
        // 제안 생성 당시의 투표권 사용 (플래시론 무력화)
        uint256 votes = govToken.getPastVotes(msg.sender, snapshot);
        _castVote(proposalId, msg.sender, votes, support);
    }
}
```

---

## 10. 실전 감사 프레임워크

### 10.1 DeFi 프로토콜 감사 체크리스트

```
AMM 체크리스트:
[ ] k 불변식이 모든 스왑 후 유지되는가?
[ ] 슬리피지 보호가 올바르게 구현되었는가?
[ ] 가격 오라클이 TWAP을 사용하는가?
[ ] CEI 패턴이 적용되었는가?
[ ] 재진입 방지가 구현되었는가?
[ ] 정수 오버플로우/언더플로우 가능성은?
[ ] tick 경계에서의 동작이 올바른가? (V3)
[ ] Hook 권한이 최소화되어 있는가? (V4)

Lending 체크리스트:
[ ] 오라클이 조작 불가능한가? (TWAP, Chainlink)
[ ] 청산 임계값이 보수적으로 설정되었는가?
[ ] 금리 모델이 극단적 시나리오에서도 안전한가?
[ ] Bad Debt 처리 메커니즘이 있는가?
[ ] 자산 유형별 위험 파라미터가 적절한가?
[ ] 청산 인센티브가 충분한가?

Bridge 체크리스트:
[ ] 메시지 재처리 방지가 있는가? (replay protection)
[ ] 검증자 키가 분산되어 있는가?
[ ] 업그레이드에 타임락이 있는가?
[ ] finality 확인 수가 충분한가?
[ ] 비상 정지 기능이 있는가?
[ ] 출금 한도가 설정되어 있는가?
```

### 10.2 불변식 기반 테스트

```solidity
// Foundry 불변식 테스트
contract AMMInvariantTest is Test {
    UniswapV2Pair pair;
    address token0;
    address token1;

    function setUp() external {
        // 초기 설정
    }

    // 이 함수는 매 퍼징 실행 후 자동으로 검사됨
    function invariant_kNeverDecreases() external {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 currentK = uint256(r0) * uint256(r1);
        uint256 expectedMinK = initialK; // setUp에서 기록한 초기 k

        // 수수료로 인해 k는 증가할 수 있으나 감소하면 안됨
        assertGe(currentK, expectedMinK, "K invariant violated");
    }

    function invariant_lpSharesSumToOne() external {
        uint256 totalSupply = pair.totalSupply();
        uint256 userABalance = pair.balanceOf(userA);
        uint256 userBBalance = pair.balanceOf(userB);

        // 모든 LP 토큰의 합 = totalSupply
        assertEq(userABalance + userBBalance, totalSupply, "LP shares mismatch");
    }
}
```

### 10.3 포크 테스트로 실제 공격 검증

```solidity
// Foundry 포크 테스트
contract EulerAttackReplay is Test {
    // 공격 블록 직전 포크
    function setUp() external {
        vm.createSelectFork("mainnet", 16_817_995); // Euler 공격 1블록 전
    }

    function test_eulerExploit() external {
        address attacker = 0x5F259D0b76665c337c6D3Eaf4f9c7f1b7EEe40a;

        // 공격자 EOA 권한으로 실행
        vm.startPrank(attacker);

        // 실제 공격 재현
        EulerAttacker attack = new EulerAttacker();
        uint256 balanceBefore = IERC20(DAI).balanceOf(attacker);
        attack.execute();
        uint256 balanceAfter = IERC20(DAI).balanceOf(attacker);

        // 공격 이익 확인
        assertGt(balanceAfter, balanceBefore, "Attack should profit");
        console2.log("Profit:", balanceAfter - balanceBefore);

        vm.stopPrank();
    }
}
```

---

## 참고 자료

- [Uniswap V4 Docs](https://docs.uniswap.org/contracts/v4/overview)
- [Curve Finance Technical](https://docs.curve.fi/)
- [ERC-4337 Specification](https://eips.ethereum.org/EIPS/eip-4337)
- [ERC-7540 Specification](https://eips.ethereum.org/EIPS/eip-7540)
- [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)
- [Trail of Bits Publications](https://github.com/trailofbits/publications)
- [Secureum Mind Maps](https://github.com/x676f64/secureum-mind_map)
- [Solodit Vulnerability DB](https://solodit.xyz)
