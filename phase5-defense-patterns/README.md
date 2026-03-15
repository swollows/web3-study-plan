# Phase 5: 방어 패턴 및 보안 도구

> 스마트 컨트랙트 보안의 핵심은 공격을 막는 것이 아니라, 공격이 성공해도 피해를 최소화하는 구조를 설계하는 것이다.

---

## 목차

1. [코드 레벨 방어 패턴](#1-코드-레벨-방어-패턴)
2. [프로토콜 레벨 방어 패턴](#2-프로토콜-레벨-방어-패턴)
3. [검증 및 테스팅 전략](#3-검증-및-테스팅-전략)
4. [보안 감사 도구 생태계](#4-보안-감사-도구-생태계)
5. [핵심 통계와 시사점](#5-핵심-통계와-시사점)
6. [실전 감사 체크리스트](#6-실전-감사-체크리스트)

---

## 1. 코드 레벨 방어 패턴

### 1.1 SafeERC20 - 반환값 호환 래퍼

#### 문제 배경

ERC-20 표준은 `transfer()`와 `transferFrom()`이 `bool`을 반환하도록 명시하지만, 일부 토큰(USDT, BNB 등)은 반환값이 없거나 항상 `true`를 반환하거나, 실패 시 revert하지 않고 `false`를 반환한다. 이를 무시하면 실패한 전송이 성공으로 처리되어 자산 손실이 발생한다.

```solidity
// 위험한 패턴: 반환값 무시
function withdrawUnsafe(address token, uint256 amount) external {
    IERC20(token).transfer(msg.sender, amount); // USDT는 반환값 없음
    // 전송 실패해도 진행됨
}

// 안전한 패턴: SafeERC20 사용
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract SafeVault {
    using SafeERC20 for IERC20;

    function withdrawSafe(address token, uint256 amount) external {
        IERC20(token).safeTransfer(msg.sender, amount);
        // 실패 시 자동으로 revert
    }

    function depositSafe(address token, uint256 amount) external {
        // approve + transferFrom 원자적 처리
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }
}
```

#### SafeERC20 내부 구현 원리

```solidity
// OpenZeppelin SafeERC20 핵심 로직 (단순화)
library SafeERC20 {
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // 저수준 call 사용으로 반환값 없는 토큰도 처리
        bytes memory returndata = address(token).functionCall(data);

        // 반환값이 있으면 true인지 확인, 없으면 통과
        if (returndata.length != 0) {
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }

    // forceApprove: approve 레이스 컨디션 방지
    // 일부 토큰은 0이 아닌 값에서 approve 시 revert
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));
        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }
}
```

#### 효과 통계 및 한계

- **효과**: ERC-20 비표준 반환값으로 인한 취약점 100% 차단
- **실제 사례**: 2022년 Qubit Finance ($80M), Meter Bridge ($4.4M) - 비표준 토큰 처리 실패
- **한계**: fee-on-transfer 토큰, rebasing 토큰은 별도 처리 필요
- **우회 가능성**: 악의적인 토큰 컨트랙트 자체의 로직은 막을 수 없음

```solidity
// fee-on-transfer 토큰 처리 패턴
function depositWithFeeHandling(address token, uint256 amount) external {
    uint256 balanceBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balanceBefore;
    // actualReceived를 amount 대신 사용
    _mint(msg.sender, actualReceived);
}
```

---

### 1.2 OpenZeppelin Initializable - 재초기화 방지

#### 문제 배경

프록시 패턴에서 `constructor`는 구현 컨트랙트에서만 실행되고 프록시에는 적용되지 않는다. `initialize()` 함수로 대체하지만, 누구나 호출할 수 있고 여러 번 호출될 수 있다.

```solidity
// 취약한 패턴
contract VulnerableProxy {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner; // 누구나 재호출 가능!
    }
}

// 안전한 패턴: OpenZeppelin Initializable
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract SecureProxy is Initializable {
    address public owner;
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // 구현 컨트랙트 직접 초기화 방지
    }

    function initialize(address _owner, uint256 _value) external initializer {
        owner = _owner;
        value = _value;
        // initializer 모디파이어가 한 번만 실행 보장
    }

    // 버전 관리가 필요한 재초기화
    function reinitialize(uint256 newValue) external reinitializer(2) {
        value = newValue;
        // reinitializer(N): 버전 N으로 한 번만 실행 가능
    }
}
```

#### Initializable 내부 메커니즘

```solidity
// 내부 상태 저장 방식 (EIP-7201 기반)
// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1))
bytes32 private constant INITIALIZABLE_STORAGE =
    0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

struct InitializableStorage {
    uint64 _initialized;   // 현재 초기화 버전
    bool _initializing;    // 초기화 진행 중 여부
}

modifier initializer() {
    InitializableStorage storage $ = _getInitializableStorage();
    bool isTopLevelCall = !$._initializing;
    require(
        (isTopLevelCall && $._initialized < 1) ||
        (!Address.isContract(address(this)) && $._initialized == 1),
        "Initializable: contract is already initialized"
    );
    $._initialized = 1;
    if (isTopLevelCall) {
        $._initializing = true;
    }
    _;
    if (isTopLevelCall) {
        $._initializing = false;
    }
}
```

#### 효과 통계 및 한계

- **효과**: 재초기화 공격 100% 방지, 구현 컨트랙트 직접 조작 방지
- **실제 사례**: 2022년 Wormhole ($320M) - 초기화 검증 우회
- **한계**: `_disableInitializers()` 누락 시 구현 컨트랙트 직접 초기화 가능
- **우회 가능성**: 스토리지 레이아웃 충돌이 있는 업그레이드로 `_initialized` 값 덮어쓰기

---

### 1.3 delegatecall 제한 패턴

#### 문제 배경

`delegatecall`은 호출자의 컨텍스트(스토리지, `msg.sender`, `msg.value`)에서 다른 컨트랙트 코드를 실행한다. 프록시 패턴의 핵심이지만, 구현 컨트랙트에서 `delegatecall`을 다시 호출하거나 자기 자신에게 `delegatecall`을 허용하면 스토리지 파괴가 발생할 수 있다.

```solidity
// 위험: 구현 컨트랙트에서 임의 delegatecall 허용
contract VulnerableImpl {
    function execute(address target, bytes calldata data) external {
        (bool success,) = target.delegatecall(data); // 공격자가 임의 코드 실행 가능
        require(success);
    }
}

// 안전: delegatecall 제한 및 자기 참조 방지
contract SecureImpl {
    address private immutable _self;

    constructor() {
        _self = address(this); // 배포 시 주소 고정
    }

    // 프록시를 통해 호출될 때만 동작 허용
    modifier onlyProxy() {
        require(address(this) != _self, "Must be called via proxy");
        _;
    }

    // 직접 호출 시에만 동작 허용 (구현 컨트랙트 보호)
    modifier notDelegated() {
        require(address(this) == _self, "Must not be delegatecall");
        _;
    }

    // 승인된 대상 목록만 delegatecall 허용
    mapping(address => bool) public approvedTargets;

    function restrictedDelegatecall(
        address target,
        bytes calldata data
    ) external onlyProxy returns (bytes memory) {
        require(approvedTargets[target], "Target not approved");
        require(target != address(this), "Self-delegatecall forbidden");
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }
}
```

#### 효과 통계 및 한계

- **효과**: 임의 코드 실행 공격 방지, 스토리지 충돌 예방
- **실제 사례**: 2021년 Poly Network ($611M) - delegatecall을 통한 권한 탈취
- **한계**: 화이트리스트 관리 비용, 정당한 use case 제한 가능성
- **우회 가능성**: 승인된 컨트랙트 자체가 취약하면 우회 가능

---

### 1.4 원자적 프록시 배포 - CPIMP 차단

#### CPIMP(Create-Proxy-Initialize-Manipulate-Proxy) 공격이란?

프록시 배포와 초기화 사이의 간격을 이용한 공격이다. 배포 후 초기화 전에 공격자가 먼저 `initialize()`를 호출해 소유권을 탈취한다.

```solidity
// 취약한 배포 방식 (두 단계 분리)
// Step 1: 프록시 배포
TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
    implementation,
    admin,
    "" // 빈 데이터 - 초기화 없음!
);
// 이 시점에서 공격자가 initialize() 호출 가능!

// Step 2: 나중에 초기화 (취약)
(bool success,) = address(proxy).call(
    abi.encodeWithSelector(Contract.initialize.selector, owner)
);

// 안전한 원자적 배포 방식
contract SecureDeployer {
    function deployAndInitialize(
        address implementation,
        address admin,
        address initialOwner
    ) external returns (address) {
        // 배포와 초기화를 한 트랜잭션에서 처리
        bytes memory initData = abi.encodeWithSelector(
            IInitializable.initialize.selector,
            initialOwner
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            implementation,
            admin,
            initData  // 배포 시 즉시 초기화
        );

        return address(proxy);
    }

    // CREATE2로 배포 주소 사전 계산 + 원자적 초기화
    function deployWithCreate2(
        bytes32 salt,
        address implementation,
        bytes calldata initData
    ) external returns (address proxy) {
        bytes memory bytecode = abi.encodePacked(
            type(TransparentUpgradeableProxy).creationCode,
            abi.encode(implementation, address(this), initData)
        );

        assembly {
            proxy := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        require(proxy != address(0), "Deploy failed");
        // initData가 constructor에서 처리되어 초기화 완료
    }
}
```

#### 효과 통계 및 한계

- **효과**: 프론트러닝 초기화 공격 100% 차단
- **실제 사례**: 2022년 Audius ($6M) - 초기화 경쟁 조건
- **한계**: CREATE2 주소 예측 가능성 (의도적 설계이나 주의 필요)
- **우회 가능성**: 초기화 함수 내부 로직에 별도 취약점 존재 시 우회 가능

---

### 1.5 EIP-1967/EIP-7201 스토리지 슬롯

#### EIP-1967: 프록시 스토리지 슬롯 표준화

프록시의 관리 변수(구현 주소, 어드민 주소)를 특정 슬롯에 저장해 구현 컨트랙트의 스토리지와 충돌을 방지한다.

```solidity
// EIP-1967 슬롯 상수
// keccak256("eip1967.proxy.implementation") - 1
bytes32 internal constant IMPLEMENTATION_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

// keccak256("eip1967.proxy.admin") - 1
bytes32 internal constant ADMIN_SLOT =
    0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

contract EIP1967Proxy {
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImpl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }
}

// EIP-7201: 네임스페이스 스토리지 패턴
// 여러 컨트랙트 변수를 하나의 격리된 네임스페이스로 관리
contract EIP7201Example {
    // 네임스페이스 슬롯 계산: keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~0xff
    // id = "myprotocol.storage.v1"
    bytes32 private constant STORAGE_LOCATION =
        0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd00;

    struct ProtocolStorage {
        uint256 totalSupply;
        mapping(address => uint256) balances;
        address owner;
        bool paused;
    }

    function _getStorage() private pure returns (ProtocolStorage storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }

    function totalSupply() public view returns (uint256) {
        return _getStorage().totalSupply;
    }
}
```

#### 효과 통계 및 한계

- **효과**: 스토리지 충돌로 인한 취약점 대폭 감소, 업그레이드 안전성 향상
- **실제 사례**: Compound, Aave 모두 EIP-1967 채택으로 업그레이드 사고 방지
- **한계**: 네임스페이스 계산 실수 시 충돌 여전히 발생 가능
- **우회 가능성**: 구현 컨트랙트가 동일한 슬롯을 직접 사용하면 충돌

---

### 1.6 곱셈 우선 규칙 - 정밀도 보존

#### 문제 배경

Solidity는 정수 나눗셈에서 소수점을 버린다(floor division). 나눗셈을 먼저 하면 이후 곱셈이 의미 없어진다.

```solidity
// 나쁜 예: 나눗셈 먼저 (정밀도 손실)
function calculateRewardBad(
    uint256 amount,
    uint256 rate,  // 예: 3
    uint256 total  // 예: 10000
) external pure returns (uint256) {
    // amount = 100, rate = 3, total = 10000
    return amount / total * rate;
    // 100 / 10000 = 0 (floor)
    // 0 * 3 = 0  (완전히 틀린 결과)
}

// 좋은 예: 곱셈 우선
function calculateRewardGood(
    uint256 amount,
    uint256 rate,
    uint256 total
) external pure returns (uint256) {
    // 100 * 3 = 300
    // 300 / 10000 = 0 (여전히 floor지만 의도된 결과)
    return amount * rate / total;
}

// 더 좋은 예: 스케일 팩터 사용
uint256 constant PRECISION = 1e18;

function calculateRewardPrecise(
    uint256 amount,
    uint256 rate,
    uint256 total
) external pure returns (uint256) {
    // 스케일업 후 연산, 마지막에 스케일다운
    uint256 scaledRate = rate * PRECISION / total;
    return amount * scaledRate / PRECISION;
    // 100 * (3 * 1e18 / 10000) / 1e18
    // = 100 * 300000000000000 / 1e18
    // = 0.03 (의도한 값에 가까움)
}

// 오버플로우 방어 + 정밀도 보존
function safeCalculate(
    uint256 a,
    uint256 b,
    uint256 denominator
) internal pure returns (uint256 result) {
    // mulDiv: 512비트 중간 계산으로 오버플로우 방지
    require(denominator > 0, "Division by zero");
    require(b == 0 || a <= type(uint256).max / b, "Overflow");
    result = a * b / denominator;
}
```

#### 효과 통계 및 한계

- **효과**: 정밀도 손실로 인한 이익 착취 방지 (특히 소액 거래 반복 공격)
- **실제 사례**: 2020년 Balancer ($500K) - 정밀도 오류 통한 토큰 드레인
- **한계**: 큰 수 곱셈 시 오버플로우 위험 증가
- **우회 가능성**: 오버플로우 방지를 위한 값 제한이 로직 버그로 이어질 수 있음

---

### 1.7 pragma 버전 고정

#### 문제 배경

부동 pragma(`^0.8.0`)는 여러 컴파일러 버전에서 컴파일되며, 버전별로 동작이 다를 수 있다. 프로덕션 컨트랙트는 특정 버전으로 고정해야 한다.

```solidity
// 나쁜 예: 부동 버전
pragma solidity ^0.8.0;  // 0.8.0 ~ 0.8.x 어디서나 컴파일

// 좋은 예: 고정 버전
pragma solidity 0.8.24;  // 정확히 이 버전만

// 라이브러리는 범위 허용 가능 (재사용성)
pragma solidity >=0.8.0 <0.9.0;

// 버전 선택 기준
// 0.8.0: unchecked arithmetic 도입
// 0.8.13: 인라인 어셈블리 개선
// 0.8.17: via-ir 파이프라인 안정화
// 0.8.20: PUSH0 opcode (Shanghai)
// 0.8.24: cancun EVM 지원 (transient storage)
```

#### 효과 통계 및 한계

- **효과**: 컴파일러 버전 불일치로 인한 예상치 못한 동작 방지
- **실제 사례**: 0.8.x와 0.7.x 간 ABI 인코딩 차이로 인한 버그 다수
- **한계**: 새 버전의 가스 최적화나 보안 패치를 받지 못함
- **우회 가능성**: 해당 없음 (컴파일 타임 체크)

---

### 1.8 RFC 6979 결정적 논스

#### 문제 배경

ECDSA 서명에서 논스(k)가 재사용되거나 예측 가능하면 개인키가 수학적으로 복원된다. RFC 6979는 메시지와 개인키에서 결정적으로 논스를 생성해 이 문제를 해결한다.

```solidity
// 온체인에서 서명 검증 시 주의사항
contract SignatureVerifier {
    // 재생 공격(Replay Attack) 방지
    mapping(bytes32 => bool) public usedSignatures;

    function verify(
        address signer,
        bytes32 messageHash,
        bytes memory signature,
        uint256 deadline,
        uint256 nonce
    ) external returns (bool) {
        // 1. 만료 확인
        require(block.timestamp <= deadline, "Signature expired");

        // 2. 논스 기반 재생 방지
        bytes32 sigHash = keccak256(abi.encodePacked(messageHash, nonce));
        require(!usedSignatures[sigHash], "Signature already used");
        usedSignatures[sigHash] = true;

        // 3. EIP-191 표준 메시지 해시
        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            messageHash
        ));

        // 4. ecrecover로 서명자 복원
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);

        // 5. 서명 가변성(malleability) 방지
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "Invalid signature s value");
        require(v == 27 || v == 28, "Invalid signature v value");

        address recovered = ecrecover(ethSignedHash, v, r, s);
        return recovered == signer && recovered != address(0);
    }

    function _splitSignature(bytes memory sig)
        internal pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
```

#### 효과 통계 및 한계

- **효과**: 논스 재사용으로 인한 개인키 노출 방지
- **실제 사례**: 2013년 Sony PS3 해킹 - 동일 논스 재사용으로 개인키 노출
- **한계**: 오프체인 서명 생성 라이브러리에 의존 (ethers.js, web3.js 모두 RFC 6979 구현)
- **우회 가능성**: 클라이언트 라이브러리가 RFC 6979를 구현하지 않으면 위험

---

### 1.9 EIP-7702 탐지 (0xef0100 접두사)

#### EIP-7702란?

EOA(Externally Owned Account)가 트랜잭션 내에서 임시로 스마트 컨트랙트 코드를 가질 수 있게 하는 새로운 계정 유형. EOA 주소의 코드 영역에 `0xef0100 || address` 형태의 위임 지정자가 설정된다.

```solidity
// EIP-7702 EOA 계정 탐지
contract EIP7702Detector {
    // 위임 지정자 매직 바이트
    bytes2 constant EIP7702_PREFIX = 0xef01;

    function isEIP7702Account(address account) public view returns (bool) {
        bytes memory code = account.code;
        if (code.length < 2) return false;
        return bytes2(code[0]) == EIP7702_PREFIX[0] &&
               bytes2(code[1]) == EIP7702_PREFIX[1];
        // 정확히는: code.length == 23 && code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00
    }

    // 더 정확한 탐지
    function detectDelegation(address account)
        public view returns (bool isDelegated, address delegatee)
    {
        bytes memory code = account.code;
        // EIP-7702 위임 지정자: 0xef 0x01 0x00 + 20바이트 주소 = 23바이트
        if (code.length == 23 &&
            code[0] == 0xef &&
            code[1] == 0x01 &&
            code[2] == 0x00)
        {
            isDelegated = true;
            assembly {
                delegatee := shr(96, mload(add(code, 35)))
            }
        }
    }

    // 보안 관련 고려사항
    function safeTransfer(address recipient, uint256 amount) external {
        // EOA라고 가정했던 주소가 EIP-7702 계정일 수 있음
        // reentrancy 가능성 재검토 필요
        (bool isDelegated,) = detectDelegation(recipient);
        if (isDelegated) {
            // 추가 검증 또는 다른 처리 경로
            require(!isDelegated || _isApprovedDelegatee(recipient),
                "EIP-7702 account requires approval");
        }
        // ... 전송 로직
    }
}
```

#### 보안 영향

EIP-7702는 기존 EOA/CA 구분을 무너뜨린다:
- `tx.origin == msg.sender` 체크가 EOA 확인으로 불충분해짐
- `extcodesize(account) == 0` 이 항상 EOA를 의미하지 않음
- EOA로부터의 콜백이 가능해져 reentrancy 공격 표면 확대

#### 효과 통계 및 한계

- **효과**: EIP-7702 계정의 예상치 못한 동작 사전 탐지
- **한계**: EIP-7702는 계속 진화 중인 표준 (2025년 기준 Pectra 하드포크 포함)
- **우회 가능성**: 위임 대상 컨트랙트의 로직에 따라 다양한 시나리오 가능

---

### 1.10 EIP-6780 SELFDESTRUCT 제한

#### EIP-6780이란?

Cancun 업그레이드(2024년 3월)에서 도입. `SELFDESTRUCT`는 이제 동일 트랜잭션 내에서 생성된 컨트랙트에만 이더를 전송하고 코드를 삭제할 수 있다. 이전에 존재한 컨트랙트에서는 이더 전송만 수행하고 코드는 삭제되지 않는다.

```solidity
// EIP-6780 이전: SELFDESTRUCT 완전 작동
contract OldPattern {
    function destroy() external {
        selfdestruct(payable(msg.sender)); // 코드 삭제 + 이더 전송
    }
    // 이 이후 address(this).code.length == 0
}

// EIP-6780 이후: 동일 트랜잭션 내 생성된 경우만 삭제
contract EIP6780Aware {
    bool private _createdInThisTx;

    constructor() {
        _createdInThisTx = true;
    }

    // 주의: 이전에 배포된 컨트랙트에서 selfdestruct 호출 시
    // 코드는 유지되고 이더만 전송됨
    function selfdestructIfNew() external {
        if (_createdInThisTx) {
            selfdestruct(payable(msg.sender)); // 완전 삭제
        } else {
            // EIP-6780 이후에는 이더만 전송, 코드는 유지
            payable(msg.sender).transfer(address(this).balance);
        }
    }
}

// 프록시 패턴에서의 영향
// - CREATE2로 배포 후 selfdestruct하고 재배포하는 패턴이 작동하지 않음
// - 의도적인 컨트랙트 파괴 메커니즘 재설계 필요
contract UpgradeableWithoutSelfdestruct {
    bool public deprecated;
    address public replacement;

    // selfdestruct 대신 소프트 폐기 패턴
    function deprecate(address newContract) external onlyOwner {
        deprecated = true;
        replacement = newContract;
    }

    modifier notDeprecated() {
        require(!deprecated, "Contract deprecated, use: " /* + Strings.toHexString(replacement) */);
        _;
    }

    modifier onlyOwner() {
        // ... owner 체크
        _;
    }
}
```

#### 효과 통계 및 한계

- **효과**: flash loan + CREATE2 + SELFDESTRUCT 재배포 공격 차단
- **실제 사례**: Tornado Cash 컨트랙트 파괴 시도, 재진입 가능한 자기파괴 패턴
- **한계**: 기존 소프트웨어와의 하위 호환성 문제, 의도적 파괴 패턴 영향
- **우회 가능성**: 동일 트랜잭션 내 생성-파괴 패턴은 여전히 가능

---

## 2. 프로토콜 레벨 방어 패턴

### 2.1 Circuit Breaker - ERC-7265

#### Circuit Breaker 패턴이란?

프로토콜에서 비정상적인 자금 유출을 감지하면 자동으로 기능을 일시 정지하는 메커니즘. 전통 금융의 서킷 브레이커와 유사하다.

```solidity
// ERC-7265 기반 Circuit Breaker 구현
interface ICircuitBreaker {
    function onTokenInflow(address token, uint256 amount) external;
    function onTokenOutflow(address token, uint256 amount) external;
}

contract CircuitBreaker is ICircuitBreaker {
    struct TokenConfig {
        uint256 minLiquidityThreshold; // 최소 유동성 임계값
        uint256 limitPeriodDuration;   // 측정 기간 (예: 4시간)
        uint256 limitPeriodPercent;    // 허용 유출 비율 (예: 15%)
        bool isProtectedToken;
    }

    struct TokenState {
        uint256 currentPeriodEnd;
        uint256 currentPeriodOutflow;
        bool isRateLimited;
        uint256 lockedAt;
    }

    mapping(address => TokenConfig) public tokenConfigs;
    mapping(address => TokenState) public tokenStates;

    uint256 constant MAX_DRAWDOWN_PERCENT = 15; // 15% 초과 유출 시 차단

    event CircuitBreakerTriggered(address indexed token, uint256 outflow, uint256 threshold);

    function onTokenOutflow(address token, uint256 amount) external override {
        TokenConfig storage config = tokenConfigs[token];
        TokenState storage state = tokenStates[token];

        if (!config.isProtectedToken) return;

        // 새 측정 기간 시작
        if (block.timestamp >= state.currentPeriodEnd) {
            state.currentPeriodEnd = block.timestamp + config.limitPeriodDuration;
            state.currentPeriodOutflow = 0;
        }

        state.currentPeriodOutflow += amount;

        // 현재 프로토콜 TVL 조회
        uint256 tvl = _getTokenBalance(token);
        uint256 threshold = tvl * config.limitPeriodPercent / 100;

        if (state.currentPeriodOutflow > threshold && tvl > config.minLiquidityThreshold) {
            state.isRateLimited = true;
            state.lockedAt = block.timestamp;
            emit CircuitBreakerTriggered(token, state.currentPeriodOutflow, threshold);
            revert("Circuit breaker: outflow limit exceeded");
        }
    }

    // 프로토콜 통합 예시
    function withdraw(address token, uint256 amount) external {
        // 서킷 브레이커 체크
        ICircuitBreaker(circuitBreaker).onTokenOutflow(token, amount);

        // 실제 출금 로직
        IERC20(token).safeTransfer(msg.sender, amount);
    }

    function _getTokenBalance(address token) internal view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    address private circuitBreaker;
}
```

#### 효과 통계 및 한계

- **효과**: **85%의 익스플로잇 차단 가능** (단일 트랜잭션 대형 탈취), 가스 오버헤드 < 1%
- **실제 사례**: Euler Finance ($197M, 2023) - 서킷 브레이커가 있었다면 대부분 차단 가능
- **한계**: 정상적인 대형 출금도 차단될 수 있음 (false positive), 파라미터 설정이 어려움
- **우회 가능성**: 여러 트랜잭션으로 분산하거나, 서킷 브레이커가 없는 다른 함수를 통해 우회

---

### 2.2 런타임 불변식 가드

#### 불변식(Invariant)이란?

프로토콜이 항상 유지해야 하는 수학적 조건. 이를 런타임에 검증하면 내부 상태 불일치를 즉시 감지할 수 있다.

```solidity
contract InvariantProtectedVault {
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    mapping(address => uint256) public userBalances;

    // 핵심 불변식 1: 개별 잔액 합 = 전체 잔액
    modifier checkBalanceInvariant() {
        _;
        _verifyBalanceInvariant();
    }

    function _verifyBalanceInvariant() internal view {
        // 이 검증은 가스 비용이 높아 프로덕션에서는 이벤트/옵션으로 관리
        uint256 contractBalance = address(this).balance;
        uint256 accountedBalance = totalDeposited - totalWithdrawn;

        // 허용 오차: 1 wei (반올림 오류)
        require(
            contractBalance >= accountedBalance &&
            contractBalance - accountedBalance <= 1,
            "Balance invariant violated"
        );
    }

    // 핵심 불변식 2: 사용자 잔액은 음수일 수 없음
    // Solidity uint256이 자동 보장하나, 오버플로우 체크

    // 핵심 불변식 3: 전체 인출 <= 전체 예치
    function withdraw(uint256 amount) external checkBalanceInvariant {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");
        userBalances[msg.sender] -= amount;
        totalWithdrawn += amount;

        // invariant: totalWithdrawn <= totalDeposited 는 항상 유지되어야
        assert(totalWithdrawn <= totalDeposited); // assert는 불변식 검증에 적합

        payable(msg.sender).transfer(amount);
    }

    // ERC-4626 스타일 불변식
    // shares * totalAssets / totalShares == expectedAssets (±1 허용)
    function _checkShareInvariant(
        uint256 shares,
        uint256 assets,
        uint256 totalShares,
        uint256 totalAssets
    ) internal pure {
        if (totalShares == 0) return;
        uint256 expected = shares * totalAssets / totalShares;
        uint256 diff = assets > expected ? assets - expected : expected - assets;
        require(diff <= 1, "Share invariant violated: rounding error exceeds 1 wei");
    }
}
```

#### 효과 통계 및 한계

- **효과**: 상태 불일치 즉시 감지, 익스플로잇 진행 중 자동 revert
- **실제 사례**: Compound의 getAccountLiquidit() 불변식이 여러 버그 조기 탐지
- **한계**: 가스 비용 증가, 복잡한 프로토콜에서 모든 불변식 정의 어려움
- **우회 가능성**: 불변식 정의 자체가 불완전하면 보호 안됨

---

### 2.3 Defense-in-Depth 전략

#### 다층 방어란?

단일 보안 레이어에 의존하지 않고, 여러 독립적인 보안 메커니즘을 중첩 배치해 하나가 뚫려도 다음 레이어가 보호하는 전략.

```
Layer 1: 코드 레벨 (SafeERC20, reentrancy guard, overflow 체크)
Layer 2: 접근 제어 (onlyOwner, roles, timelocks)
Layer 3: 경제적 제한 (circuit breaker, rate limiting, max amounts)
Layer 4: 모니터링 (이벤트, on-chain oracle, 멀티시그 알림)
Layer 5: 긴급 대응 (pause, emergency withdrawal, upgrade)
```

```solidity
// Defense-in-Depth 예시: 5레이어 보호
contract DefenseInDepthVault {
    // Layer 1: ReentrancyGuard
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "Reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    // Layer 2: 역할 기반 접근 제어
    mapping(address => bool) public isOperator;
    modifier onlyOperator() {
        require(isOperator[msg.sender], "Not operator");
        _;
    }

    // Layer 3: 경제적 제한
    uint256 public constant MAX_SINGLE_WITHDRAWAL = 100 ether;
    uint256 public dailyWithdrawalUsed;
    uint256 public dailyWithdrawalLimit = 1000 ether;
    uint256 public lastWithdrawalReset;

    modifier withinDailyLimit(uint256 amount) {
        if (block.timestamp > lastWithdrawalReset + 1 days) {
            dailyWithdrawalUsed = 0;
            lastWithdrawalReset = block.timestamp;
        }
        require(amount <= MAX_SINGLE_WITHDRAWAL, "Exceeds single tx limit");
        require(dailyWithdrawalUsed + amount <= dailyWithdrawalLimit, "Daily limit exceeded");
        dailyWithdrawalUsed += amount;
        _;
    }

    // Layer 4: 이벤트 기반 모니터링
    event LargeWithdrawal(address indexed user, uint256 amount, uint256 timestamp);

    // Layer 5: 긴급 정지
    bool public paused;
    modifier whenNotPaused() {
        require(!paused, "Contract paused");
        _;
    }

    function withdraw(uint256 amount)
        external
        nonReentrant          // Layer 1
        whenNotPaused         // Layer 5
        withinDailyLimit(amount) // Layer 3
    {
        // Layer 4: 대형 출금 이벤트
        if (amount > 10 ether) {
            emit LargeWithdrawal(msg.sender, amount, block.timestamp);
        }

        // 실제 로직
        _processWithdrawal(msg.sender, amount);
    }

    function _processWithdrawal(address user, uint256 amount) internal {
        // ... 출금 처리
    }
}
```

#### 효과 통계 및 한계

- **효과**: **87%의 보안 침해 감소** (다층 방어 적용 프로토콜 vs 단층 방어)
- **실제 사례**: Uniswap V3 - 여러 독립적인 보안 레이어로 대형 익스플로잇 없음
- **한계**: 복잡성 증가로 개발/감사 비용 상승, 레이어 간 상호작용 버그 가능
- **우회 가능성**: 모든 레이어를 동시에 우회하는 복합 공격 이론적으로 가능

---

### 2.4 타임락과 긴급 정지

#### 타임락(Timelock)

거버넌스 결정이나 중요한 파라미터 변경에 의무적인 지연 시간을 부과해 커뮤니티가 반응할 시간을 확보한다.

```solidity
contract TimelockController {
    uint256 public constant MIN_DELAY = 2 days;
    uint256 public constant MAX_DELAY = 30 days;

    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;        // 실행 가능 시간
        bool executed;
        bool cancelled;
    }

    mapping(bytes32 => Transaction) public transactions;

    event TransactionQueued(bytes32 indexed txHash, address target, uint256 eta);
    event TransactionExecuted(bytes32 indexed txHash);

    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 delay
    ) external onlyGovernance returns (bytes32) {
        require(delay >= MIN_DELAY && delay <= MAX_DELAY, "Invalid delay");

        bytes32 txHash = keccak256(abi.encode(target, value, data, block.timestamp));
        uint256 eta = block.timestamp + delay;

        transactions[txHash] = Transaction({
            target: target,
            value: value,
            data: data,
            eta: eta,
            executed: false,
            cancelled: false
        });

        emit TransactionQueued(txHash, target, eta);
        return txHash;
    }

    function executeTransaction(bytes32 txHash) external payable onlyGovernance {
        Transaction storage txn = transactions[txHash];

        require(!txn.executed, "Already executed");
        require(!txn.cancelled, "Transaction cancelled");
        require(block.timestamp >= txn.eta, "Timelock not elapsed");
        require(block.timestamp <= txn.eta + 14 days, "Transaction expired");

        txn.executed = true;

        (bool success, bytes memory result) = txn.target.call{value: txn.value}(txn.data);
        require(success, string(result));

        emit TransactionExecuted(txHash);
    }

    modifier onlyGovernance() { _; } // 실제 거버넌스 체크
}

// 긴급 정지: 50-70% 임계값 패턴
contract EmergencyStop {
    mapping(address => bool) public guardians;
    uint256 public guardianCount;
    uint256 public approvalCount;
    bool public emergencyStopped;

    uint256 public constant EMERGENCY_THRESHOLD_PERCENT = 50; // 50% 이상 동의

    mapping(bytes32 => mapping(address => bool)) public emergencyVotes;

    function voteForEmergencyStop(bytes32 reason) external {
        require(guardians[msg.sender], "Not a guardian");
        require(!emergencyVotes[reason][msg.sender], "Already voted");

        emergencyVotes[reason][msg.sender] = true;

        uint256 votes = _countVotes(reason);
        uint256 threshold = guardianCount * EMERGENCY_THRESHOLD_PERCENT / 100;

        if (votes >= threshold) {
            emergencyStopped = true;
            emit EmergencyStopActivated(reason, votes);
        }
    }

    function _countVotes(bytes32 reason) internal view returns (uint256 count) {
        // ... 투표 집계
    }

    event EmergencyStopActivated(bytes32 reason, uint256 votes);
}
```

#### 효과 통계 및 한계

- **효과**: 악의적 거버넌스 공격 시 커뮤니티 반응 시간 확보, 돌발 러그풀 방지
- **실제 사례**: 2022년 Fei Protocol 타임락으로 악의적 제안 커뮤니티 거부
- **한계**: 긴급 상황에서 빠른 패치 불가, 타임락 자체를 우회하는 거버넌스 공격 가능
- **우회 가능성**: 타임락 컨트롤러 자체에 대한 권한을 탈취하면 우회 가능

---

### 2.5 Snapshot 투표 - Flash Loan 거버넌스 방지

#### 문제 배경

온체인 거버넌스에서 투표 파워가 특정 블록의 토큰 잔액을 기준으로 하면, 공격자가 flash loan으로 대량의 토큰을 빌려 투표를 조작할 수 있다.

```solidity
// 취약한 투표 시스템
contract VulnerableGovernance {
    ERC20 public token;

    function castVote(uint256 proposalId, bool support) external {
        // 현재 블록의 잔액 사용 - flash loan 가능!
        uint256 votes = token.balanceOf(msg.sender);
        _recordVote(proposalId, msg.sender, support, votes);
    }
}

// 안전한 스냅샷 투표 (ERC-20Votes 사용)
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

contract SecureGovernance {
    ERC20Votes public token;

    struct Proposal {
        uint256 snapshotBlock; // 제안 시점 블록
        uint256 startTime;
        uint256 endTime;
        uint256 forVotes;
        uint256 againstVotes;
    }

    mapping(uint256 => Proposal) public proposals;

    function createProposal() external returns (uint256 proposalId) {
        proposalId = _nextProposalId++;
        proposals[proposalId] = Proposal({
            snapshotBlock: block.number - 1, // 현재 블록 이전 스냅샷
            startTime: block.timestamp + 1 days, // 투표 시작 전 지연
            endTime: block.timestamp + 8 days,
            forVotes: 0,
            againstVotes: 0
        });
    }

    function castVote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.timestamp >= proposal.startTime, "Voting not started");
        require(block.timestamp <= proposal.endTime, "Voting ended");

        // 스냅샷 블록의 투표 파워 사용 (flash loan 불가)
        uint256 votes = token.getPastVotes(msg.sender, proposal.snapshotBlock);
        require(votes > 0, "No voting power at snapshot");

        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }
    }

    uint256 private _nextProposalId = 1;
}

// ERC-20Votes: 체크포인트 기반 투표 파워 추적
contract GovernanceToken is ERC20Votes {
    constructor() ERC20("Gov", "GOV") EIP712("Gov", "1") {}

    // 전송 시 자동으로 체크포인트 기록
    // getPastVotes(account, blockNumber): 과거 블록의 투표 파워 조회
}
```

#### 효과 통계 및 한계

- **효과**: Flash loan을 이용한 거버넌스 조작 완전 차단
- **실제 사례**: 2022년 Beanstalk ($182M) - 스냅샷 없는 온체인 거버넌스 조작
- **한계**: 과거 블록 스냅샷 저장으로 가스 비용 및 스토리지 증가
- **우회 가능성**: 장기간 토큰 축적 후 공격 (시간 비용은 높아짐)

---

### 2.6 Commit-Reveal과 전송 쿨다운

```solidity
// Commit-Reveal: MEV 및 프론트러닝 방지
contract CommitReveal {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitBlock;

    uint256 constant MIN_REVEAL_DELAY = 1; // 최소 1블록 후 reveal
    uint256 constant MAX_REVEAL_DELAY = 256; // 최대 256블록 (blockhash 한계)

    function commit(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        commitBlock[msg.sender] = block.number;
    }

    function reveal(uint256 amount, bytes32 salt) external {
        bytes32 commitment = commitments[msg.sender];
        require(commitment != bytes32(0), "No commitment");

        uint256 blockDelta = block.number - commitBlock[msg.sender];
        require(blockDelta >= MIN_REVEAL_DELAY, "Too early");
        require(blockDelta <= MAX_REVEAL_DELAY, "Commitment expired");

        // 커밋 검증
        require(
            keccak256(abi.encodePacked(msg.sender, amount, salt)) == commitment,
            "Invalid reveal"
        );

        // 커밋 삭제 후 실행 (재생 방지)
        delete commitments[msg.sender];
        _execute(msg.sender, amount);
    }

    function _execute(address user, uint256 amount) internal { /* ... */ }
}

// 전송 쿨다운: 봇 공격 및 플래시 공격 완화
contract CooldownProtected {
    mapping(address => uint256) public lastActionTime;
    uint256 public constant COOLDOWN = 1 hours;

    modifier withCooldown() {
        require(
            block.timestamp >= lastActionTime[msg.sender] + COOLDOWN,
            "Cooldown active"
        );
        lastActionTime[msg.sender] = block.timestamp;
        _;
    }

    function sensitiveAction() external withCooldown {
        // 핵심 로직
    }
}
```

---

### 2.7 L2 시퀀서 업타임 체크

#### 문제 배경

L2(Arbitrum, Optimism 등)에서 오라클 가격을 사용할 때, 시퀀서가 오프라인이면 가격이 오래된 값으로 고정된다. 이를 이용해 공격자가 L1에서 가격을 조작하고 L2 오프라인 상태에서 유리한 포지션을 차지할 수 있다.

```solidity
// Chainlink L2 시퀀서 업타임 피드 통합
interface ISequencerUptimeFeed {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,      // 0 = 업타임, 1 = 다운타임
        uint256 startedAt,  // 시퀀서 상태 변경 시간
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

contract L2SafeOracle {
    ISequencerUptimeFeed public sequencerFeed;
    AggregatorV3Interface public priceFeed;

    uint256 constant GRACE_PERIOD = 1 hours; // 시퀀서 복구 후 대기 시간

    // Arbitrum: 0xFdB631F5EE196F0ed6FAa767959853A9F217697D
    // Optimism: 0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389
    constructor(address _sequencerFeed, address _priceFeed) {
        sequencerFeed = ISequencerUptimeFeed(_sequencerFeed);
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function getSafePrice() external view returns (int256) {
        // 1. 시퀀서 업타임 확인
        (
            ,
            int256 sequencerAnswer,
            uint256 sequencerStartedAt,
            ,
        ) = sequencerFeed.latestRoundData();

        // 0 = 업, 1 = 다운
        bool isSequencerUp = sequencerAnswer == 0;
        require(isSequencerUp, "L2 sequencer is down");

        // 2. 그레이스 피리어드 확인 (시퀀서 재시작 직후 불안정)
        uint256 timeSinceSequencerUp = block.timestamp - sequencerStartedAt;
        require(timeSinceSequencerUp > GRACE_PERIOD, "Grace period not elapsed");

        // 3. 가격 피드 staleness 확인
        (
            ,
            int256 price,
            ,
            uint256 updatedAt,
        ) = priceFeed.latestRoundData();

        require(block.timestamp - updatedAt <= 3600, "Price feed stale");
        require(price > 0, "Invalid price");

        return price;
    }
}
```

#### 효과 통계 및 한계

- **효과**: L2 시퀀서 다운타임을 이용한 오라클 조작 공격 방지
- **실제 사례**: 2023년 여러 L2 DeFi 프로토콜에서 시퀀서 다운 시 잘못된 청산 발생
- **한계**: 그레이스 피리어드 동안 프로토콜 기능 일시 중단
- **우회 가능성**: 시퀀서 자체가 악의적이라면 (중앙화 위험)

---

## 3. 검증 및 테스팅 전략

### 3.1 형식 검증(Formal Verification) vs 퍼징(Fuzzing)

#### 상보적 접근법

두 방법은 서로 다른 종류의 버그를 찾는다. 함께 사용할 때 최대 효과를 발휘한다.

```
형식 검증:
- 수학적으로 모든 가능한 입력에 대해 속성을 증명
- 100% 확신이지만 증명 가능한 속성만 검증
- 적합: 산술 오버플로우, 접근 제어 로직, 상태 전이

퍼징:
- 랜덤/생성된 입력으로 실제 실행 테스트
- 반례를 찾거나 못찾을 수 있음 (완전하지 않음)
- 적합: 복잡한 상태 상호작용, 예상치 못한 입력 조합
```

```solidity
// Foundry Fuzz Test 예시
contract VaultFuzzTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    // 퍼징: 임의 금액, 임의 시간으로 테스트
    function testFuzz_withdrawNeverExceedsBalance(
        uint256 depositAmount,
        uint256 withdrawAmount,
        uint256 timeSkip
    ) public {
        // 입력 범위 제한
        depositAmount = bound(depositAmount, 1 wei, 1000 ether);
        withdrawAmount = bound(withdrawAmount, 0, depositAmount);
        timeSkip = bound(timeSkip, 0, 365 days);

        // 시나리오 실행
        vault.deposit{value: depositAmount}();
        skip(timeSkip);

        uint256 balanceBefore = address(this).balance;
        vault.withdraw(withdrawAmount);
        uint256 balanceAfter = address(this).balance;

        // 불변식: 인출된 금액 <= 예치된 금액
        assertLe(balanceAfter - balanceBefore, depositAmount);

        // 불변식: 컨트랙트 잔액은 항상 0 이상
        assertGe(address(vault).balance, 0);
    }

    // 불변식 테스트: 모든 실행 후 유지되어야 하는 속성
    function invariant_totalSupplyEqualsBalances() public view {
        // 모든 사용자 잔액의 합 == totalSupply
        uint256 sum = 0;
        for (uint i = 0; i < users.length; i++) {
            sum += vault.balanceOf(users[i]);
        }
        assertEq(sum, vault.totalSupply());
    }

    address[] internal users;
}
```

### 3.2 KEVM 형식 의미론

#### KEVM이란?

K 프레임워크를 사용한 EVM의 형식적 명세. Solidity 코드를 EVM 바이트코드 수준에서 수학적으로 검증한다.

```
KEVM 검증 흐름:
1. Solidity 코드 -> EVM 바이트코드 컴파일
2. K 명세로 속성 정의 (사전조건, 사후조건)
3. KEVM으로 모든 실행 경로 탐색
4. 속성 위반 케이스 발견 시 반례 제공

예시 K 명세 (의사코드):
rule <k> TRANSFER(to, amount) => . </k>
     <caller> from </caller>
     <account>
       <id> from </id>
       <balance> B => B -Int amount </balance>
     </account>
     requires amount <=Int B andBool amount >Int 0
```

### 3.3 불변식 작성 (검증 작업의 80%)

불변식은 "항상 참이어야 하는 조건"이며, 좋은 불변식 작성이 형식 검증 작업의 대부분을 차지한다.

```solidity
// 좋은 불변식 예시들
contract InvariantExamples {
    // 1. 자산 보존 불변식
    // totalAssets == sum(allUserShares) * sharePrice

    // 2. 단조성 불변식
    // lastUpdateTime은 항상 증가해야 함
    uint256 public lastUpdateTime;
    function update() external {
        uint256 newTime = block.timestamp;
        assert(newTime >= lastUpdateTime); // 단조 증가
        lastUpdateTime = newTime;
    }

    // 3. 경계 불변식
    // 0 <= utilization <= 100%
    function getUtilization() public view returns (uint256) {
        if (totalLiquidity == 0) return 0;
        uint256 util = totalBorrowed * 1e18 / totalLiquidity;
        assert(util <= 1e18); // 100% 초과 불가
        return util;
    }

    // 4. 대칭 불변식
    // deposit(x) 후 withdraw(x) 하면 상태 복원

    // 5. 접근 제어 불변식
    // onlyOwner 함수는 owner 외 호출 불가

    uint256 public totalBorrowed;
    uint256 public totalLiquidity;
}
```

### 3.4 Property-Based Testing

```solidity
// Echidna (퍼징 도구) 스타일 속성 테스트
contract EchidnaTest {
    Token token;

    constructor() {
        token = new Token();
        token.mint(address(this), 1000e18);
    }

    // echidna_: 항상 true여야 하는 속성 (접두사 규칙)
    function echidna_balance_never_negative() public view returns (bool) {
        return token.balanceOf(address(this)) >= 0; // uint이므로 항상 true이나 로직 검증용
    }

    function echidna_total_supply_constant() public view returns (bool) {
        return token.totalSupply() == 1000e18; // 발행량 불변
    }

    // Handler: Echidna가 호출할 수 있는 실제 동작
    function transfer_handler(address to, uint256 amount) public {
        amount = amount % (token.balanceOf(address(this)) + 1); // 보유량 이하로 제한
        token.transfer(to, amount);
    }
}
```

---

## 4. 보안 감사 도구 생태계

### 4.1 정적 분석 도구

#### Slither
- **종류**: 정적 분석 (Python 기반)
- **특징**: 70+ 내장 검사기, 빠른 실행 (초 단위)
- **탐지**: reentrancy, 미사용 반환값, 정수 오버플로우, 접근 제어
- **한계**: false positive 다수, 복잡한 비즈니스 로직 이해 못함

```bash
slither contracts/ --detect reentrancy-eth,suicidal,arbitrary-send
slither contracts/ --print call-graph  # 호출 그래프 출력
slither contracts/ --checklist         # 감사 체크리스트 생성
```

#### Aderyn
- **종류**: 정적 분석 (Rust 기반, Cyfrin 개발)
- **특징**: AST 기반 분석, 마크다운 리포트 자동 생성
- **탐지**: Slither 유사하나 다른 패턴셋

```bash
aderyn contracts/ --output report.md
```

#### Semgrep
- **종류**: 패턴 매칭 기반 정적 분석
- **특징**: 커스텀 규칙 작성 가능, CI/CD 통합 용이

```yaml
# Semgrep 커스텀 규칙 예시
rules:
  - id: unsafe-delegatecall
    patterns:
      - pattern: $ADDR.delegatecall($DATA)
    message: "Unsafe delegatecall detected"
    languages: [solidity]
    severity: ERROR
```

### 4.2 형식 검증 도구

#### Certora Prover
- **종류**: 형식 검증 (SMT solver 기반)
- **특징**: CVL(Certora Verification Language)로 속성 명세
- **탐지**: 모든 입력에 대한 수학적 증명

```javascript
// CVL 명세 예시
rule withdraw_correct(address user, uint256 amount) {
    env e;
    uint256 balanceBefore = balanceOf(user);

    withdraw(e, amount);

    uint256 balanceAfter = balanceOf(user);

    // 인출 후 잔액은 정확히 amount만큼 감소
    assert balanceAfter == balanceBefore - amount;

    // 인출액은 보유액 초과 불가
    assert amount <= balanceBefore;
}
```

#### KEVM
- **종류**: EVM 바이트코드 수준 형식 검증
- **특징**: 가장 낮은 레벨의 검증, 컴파일러 버그도 탐지 가능

### 4.3 Claude Code Skills

#### 보안 감사 전문 스킬

1. **Pashov 감사 스킬** (1개 패턴): 유명 독립 감사인 Pashov의 방법론 기반
   - 고수준 아키텍처 리뷰
   - 비즈니스 로직 검증
   - 위협 모델링

2. **Trail of Bits 스킬** (35+ 패턴): 최고 수준의 보안 회사 방법론
   - reentrancy 패턴 35가지 이상
   - 암호화 취약점
   - 가스 최적화 버그

3. **Cyfrin 스킬** (1개 패턴): Patrick Collins 팀 방법론
   - 교육적 접근법
   - FREI-PI 체크리스트

4. **SCV-scan 스킬** (36 패턴): 체계적인 취약점 분류
   - 36가지 취약점 패턴 체계적 스캔
   - 우선순위 기반 리포팅

5. **QuillShield 스킬** (10 패턴): QuillAudits 방법론
   - 10가지 핵심 취약점 포커스
   - 빠른 초기 스캔

6. **SC-Auditor 스킬** (4 MCP): MCP 기반 감사 도구
   - 4가지 MCP(Method, Context, Pattern) 기반 심층 분석

### 4.4 4단계 감사 워크플로우

```
Phase 1: 자동화 스캔 (1-2일)
├── Slither / Aderyn 실행
├── Semgrep 커스텀 규칙 적용
├── 이슈 분류 및 false positive 필터링
└── 자동화로 발견된 고심각도 이슈 즉시 보고

Phase 2: 수동 코드 리뷰 (3-5일)
├── 비즈니스 로직 이해
├── 위협 모델 구축
├── 데이터 흐름 추적
└── 신뢰 경계 분석

Phase 3: 형식 검증 (2-3일)
├── 핵심 불변식 정의
├── Certora/KEVM으로 속성 증명
└── 퍼징으로 경계 케이스 탐색

Phase 4: 보고서 작성 및 재감사 (1-2일)
├── 발견 사항 문서화 (Critical/High/Medium/Low/Info)
├── PoC 익스플로잇 작성
├── 개발팀 수정 검토
└── 재감사 (fix review)
```

---

## 5. 핵심 통계와 시사점

### 5.1 감사 후 해킹 통계

**2025년 기준 92%의 해킹은 이전에 감사를 받은 컨트랙트에서 발생했다.**

이 통계는 감사가 의미 없다는 것이 아니라, 감사의 한계를 보여준다:

```
감사가 놓치는 주요 원인:
1. 감사 이후 새 코드 추가 (40%)
2. 복잡한 프로토콜 상호작용 (30%)
3. 경제적/오라클 취약점 (20%)
4. 사회공학/키 관리 실수 (10%)
```

### 5.2 자동화 vs 인간 감사

```
자동화 도구 (60%):
- 장점: 빠름, 일관성, 알려진 패턴 100% 탐지
- 단점: 비즈니스 로직 이해 불가, false positive
- 적합: 알려진 취약점 패턴, 코드 품질 체크

인간 감사 (40%):
- 장점: 맥락 이해, 창의적 공격 발견
- 단점: 느림, 일관성 부족, 비용
- 적합: 복잡한 로직, 새로운 공격 벡터
```

### 5.3 FV vs 퍼징: 다른 버그 클래스

```
형식 검증이 잘 찾는 버그:
- 정밀도 오류 (정확한 조건 명세 가능)
- 접근 제어 위반
- 단조성 위반 (증가만 해야 하는데 감소)
- 수학적 속성 위반

퍼징이 잘 찾는 버그:
- 복잡한 상태 상호작용
- 예상치 못한 입력 조합
- 레이스 컨디션 (멀티콜)
- 경계값 버그

결론: 두 방법은 서로 보완적이며 함께 사용해야 한다.
```

---

## 6. 실전 감사 체크리스트

### 고심각도 체크리스트

```
[ ] Reentrancy: 외부 호출 후 상태 변경이 있는가?
[ ] Access Control: 모든 특권 함수에 접근 제어가 있는가?
[ ] Integer Overflow: unchecked 블록 외 산술 연산 검토
[ ] Flash Loan: 단일 트랜잭션 가격 조작 가능한가?
[ ] Oracle Manipulation: 오라클 소스가 조작 가능한가?
[ ] Reentrancy via ERC-777/ERC-1155: 토큰 훅 악용 가능한가?
[ ] Cross-function Reentrancy: 같은 컨트랙트 다른 함수로 재진입?
[ ] Read-Only Reentrancy: view 함수 통한 불일치 상태 읽기?
[ ] Proxy Storage Collision: 프록시와 구현의 스토리지 슬롯 충돌?
[ ] Uninitialized Proxy: initialize() 호출 전 상태 확인?
```

### 중간 심각도 체크리스트

```
[ ] Precision Loss: 나눗셈 전 곱셈 수행하는가?
[ ] Timestamp Dependence: block.timestamp를 엄격한 조건에 사용하는가?
[ ] Signature Replay: 사용된 서명 재사용 방지되는가?
[ ] ERC20 Return Value: SafeERC20 또는 반환값 체크하는가?
[ ] Approval Race Condition: approve(0) 후 approve(N) 패턴 사용하는가?
[ ] Gas Griefing: 낮은 가스로 서브콜 실패 가능한가?
[ ] Centralization Risk: 단일 키가 전체 프로토콜 제어하는가?
[ ] Upgradability Risk: 업그레이드가 의도치 않게 스토리지 손상하는가?
```

### 저심각도 / 정보성 체크리스트

```
[ ] Event Emission: 모든 중요 상태 변경에 이벤트 발생?
[ ] NatSpec 주석: 함수 의도 문서화?
[ ] Magic Numbers: 상수값에 설명적 이름 부여?
[ ] Error Messages: require/revert에 의미 있는 메시지?
[ ] Test Coverage: 분기 커버리지 90% 이상?
[ ] Compiler Warnings: 모든 경고 해소?
```

---

## 정리

스마트 컨트랙트 보안은 단일 기법이 아니라 여러 방어 레이어의 조합이다.

- **코드 레벨**: SafeERC20, Initializable, pragma 고정 등으로 알려진 패턴 버그 제거
- **프로토콜 레벨**: Circuit Breaker, Timelock, Snapshot 투표로 경제적 공격 방어
- **검증**: FV와 퍼징의 상보적 사용으로 수학적 정확성 보장
- **도구**: 자동화(60%)와 인간 감사(40%)의 결합

92%의 감사 통과 후 해킹이라는 통계는 지속적인 보안 모니터링과 방어적 설계의 필요성을 시사한다. 좋은 보안은 코드를 배포한 순간 끝나는 것이 아니라 지속적인 과정이다.
