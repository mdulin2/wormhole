// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

import {IRelayProvider} from "../../contracts/interfaces/relayer/IRelayProvider.sol";
import {RelayProvider} from "../../contracts/relayer/relayProvider/RelayProvider.sol";
import {RelayProviderSetup} from "../../contracts/relayer/relayProvider/RelayProviderSetup.sol";
import {RelayProviderImplementation} from
    "../../contracts/relayer/relayProvider/RelayProviderImplementation.sol";
import {RelayProviderProxy} from "../../contracts/relayer/relayProvider/RelayProviderProxy.sol";
import {RelayProviderMessages} from
    "../../contracts/relayer/relayProvider/RelayProviderMessages.sol";
import {RelayProviderStructs} from "../../contracts/relayer/relayProvider/RelayProviderStructs.sol";
import {IWormholeRelayer} from "../../contracts/interfaces/relayer/IWormholeRelayer.sol";
import {IDelivery} from "../../contracts/interfaces/relayer/IDelivery.sol";
import {CoreRelayer} from "../../contracts/relayer/coreRelayer/CoreRelayer.sol";
import {IWormholeRelayerInternalStructs} from
    "../../contracts/interfaces/relayer/IWormholeRelayerInternalStructs.sol";
import {CoreRelayerSetup} from "../../contracts/relayer/coreRelayer/CoreRelayerSetup.sol";
import {CoreRelayerMessages} from "../../contracts/relayer/coreRelayer/CoreRelayerMessages.sol";
import {ForwardWrapper} from "../../contracts/relayer/coreRelayer/ForwardWrapper.sol";
import {MockGenericRelayer} from "./MockGenericRelayer.sol";
import {MockWormhole} from "./MockWormhole.sol";
import {IWormhole} from "../../contracts/interfaces/IWormhole.sol";
import {WormholeSimulator, FakeWormholeSimulator} from "./WormholeSimulator.sol";
import {IWormholeReceiver} from "../../contracts/interfaces/relayer/IWormholeReceiver.sol";
import {AttackForwardIntegration} from "./AttackForwardIntegration.sol";
import {MockRelayerIntegration, Structs} from "../../contracts/mock/MockRelayerIntegration.sol";
import {ForwardTester} from "./ForwardTester.sol";
import {TestHelpers} from "./TestHelpers.sol";
import "../../contracts/libraries/external/BytesLib.sol";

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "forge-std/Vm.sol";

contract WormholeRelayerGovernanceTests is Test {
    using BytesLib for bytes;

    TestHelpers helpers;

    bytes32 relayerModule = 0x000000000000000000000000000000000000000000436F726552656C61796572;
    IWormhole wormhole;
    IRelayProvider relayProvider;
    WormholeSimulator wormholeSimulator;
    IWormholeRelayer wormholeRelayer;

    function setUp() public {
        helpers = new TestHelpers();
        (wormhole, wormholeSimulator) = helpers.setUpWormhole(1);
        relayProvider = helpers.setUpRelayProvider(1);
        wormholeRelayer = helpers.setUpCoreRelayer(1, wormhole, address(relayProvider));
    }

    struct GovernanceStack {
        bytes message;
        IWormhole.VM preSignedMessage;
        bytes signed;
    }

    function signMessage(bytes memory message) internal returns (bytes memory signed) {
        IWormhole.VM memory preSignedMessage = IWormhole.VM({
            version: 1,
            timestamp: uint32(block.timestamp),
            nonce: 0,
            emitterChainId: wormhole.governanceChainId(),
            emitterAddress: wormhole.governanceContract(),
            sequence: 0,
            consistencyLevel: 200,
            payload: message,
            guardianSetIndex: 0,
            signatures: new IWormhole.Signature[](0),
            hash: bytes32("")
        });
        signed = wormholeSimulator.encodeAndSignMessage(preSignedMessage);
    }

    function fillInGovernanceStack(bytes memory message)
        internal
        returns (GovernanceStack memory stack)
    {
        stack.message = message;
        stack.preSignedMessage = IWormhole.VM({
            version: 1,
            timestamp: uint32(block.timestamp),
            nonce: 0,
            emitterChainId: wormhole.governanceChainId(),
            emitterAddress: wormhole.governanceContract(),
            sequence: 0,
            consistencyLevel: 200,
            payload: message,
            guardianSetIndex: 0,
            signatures: new IWormhole.Signature[](0),
            hash: bytes32("")
        });
        stack.signed = wormholeSimulator.encodeAndSignMessage(stack.preSignedMessage);
    }

    function testSetDefaultRelayProvider() public {
        IRelayProvider relayProviderB = helpers.setUpRelayProvider(1);
        IRelayProvider relayProviderC = helpers.setUpRelayProvider(1);

        bytes memory signed = signMessage(
            abi.encodePacked(
                relayerModule,
                uint8(4),
                uint16(1),
                bytes32(uint256(uint160(address(relayProviderB))))
            )
        );

        CoreRelayer(payable(address(wormholeRelayer))).setDefaultRelayProvider(signed);

        assertTrue(wormholeRelayer.getDefaultRelayProvider() == address(relayProviderB));

        signed = signMessage(
            abi.encodePacked(
                relayerModule,
                uint8(4),
                uint16(1),
                bytes32(uint256(uint160(address(relayProviderC))))
            )
        );

        CoreRelayer(payable(address(wormholeRelayer))).setDefaultRelayProvider(signed);

        assertTrue(wormholeRelayer.getDefaultRelayProvider() == address(relayProviderC));
    }

    function testRegisterChain() public {
        IWormholeRelayer wormholeRelayer1 =
            helpers.setUpCoreRelayer(1, wormhole, address(relayProvider));
        IWormholeRelayer wormholeRelayer2 =
            helpers.setUpCoreRelayer(1, wormhole, address(relayProvider));
        IWormholeRelayer wormholeRelayer3 =
            helpers.setUpCoreRelayer(1, wormhole, address(relayProvider));

        helpers.registerCoreRelayerContract(
            CoreRelayer(payable(address(wormholeRelayer1))),
            wormhole,
            1,
            2,
            wormholeRelayer.toWormholeFormat(address(wormholeRelayer2))
        );

        helpers.registerCoreRelayerContract(
            CoreRelayer(payable(address(wormholeRelayer1))),
            wormhole,
            1,
            3,
            wormholeRelayer.toWormholeFormat(address(wormholeRelayer3))
        );

        assertTrue(
            CoreRelayer(payable(address(wormholeRelayer1))).registeredCoreRelayerContract(2)
                == wormholeRelayer1.toWormholeFormat(address(wormholeRelayer2))
        );

        assertTrue(
            CoreRelayer(payable(address(wormholeRelayer1))).registeredCoreRelayerContract(3)
                == wormholeRelayer1.toWormholeFormat(address(wormholeRelayer3))
        );

        helpers.registerCoreRelayerContract(
            CoreRelayer(payable(address(wormholeRelayer1))),
            wormhole,
            1,
            3,
            wormholeRelayer.toWormholeFormat(address(wormholeRelayer2))
        );

        assertTrue(
            CoreRelayer(payable(address(wormholeRelayer1))).registeredCoreRelayerContract(3)
                == wormholeRelayer1.toWormholeFormat(address(wormholeRelayer2))
        );
    }

    function testUpgradeContractToItself() public {
        address payable myCoreRelayer = payable(
            address(helpers.setUpCoreRelayer(wormhole.chainId(), wormhole, address(relayProvider)))
        );

        for (uint256 i = 0; i < 10; i++) {
            address forwardWrapper = address(new ForwardWrapper(myCoreRelayer, address(wormhole)));
            CoreRelayer coreRelayerImplementationNew = new CoreRelayer(forwardWrapper);

            bytes memory message = abi.encodePacked(
                relayerModule,
                uint8(2),
                uint16(1),
                wormholeRelayer.toWormholeFormat(address(coreRelayerImplementationNew))
            );

            bytes memory signed = signMessage(message);

            CoreRelayer(myCoreRelayer).submitContractUpgrade(signed);

            CoreRelayer(myCoreRelayer).getDefaultRelayProvider();
        }

        bytes memory brickedMessage = abi.encodePacked(
            relayerModule,
            uint8(2),
            uint16(1),
            wormholeRelayer.toWormholeFormat(address(new RelayProviderImplementation()))
        );
        CoreRelayer(myCoreRelayer).submitContractUpgrade(signMessage(brickedMessage));

        vm.expectRevert();
        CoreRelayer(myCoreRelayer).getDefaultRelayProvider();
    }

    function testRecoverChainId() public {
        address payable myCoreRelayer = payable(
            address(helpers.setUpCoreRelayer(wormhole.chainId(), wormhole, address(relayProvider)))
        );
        CoreRelayer mcr = CoreRelayer(payable(myCoreRelayer));
        assertTrue(mcr.chainId() == wormhole.chainId());
        assertTrue(mcr.evmChainId() == block.chainid);

        // fork!
        vm.chainId(12345);
        assertTrue(mcr.evmChainId() != block.chainid);

        bytes memory message = abi.encodePacked(relayerModule, uint8(3), uint256(12345), uint16(27));

        bytes memory signed = signMessage(message);

        CoreRelayer(myCoreRelayer).submitRecoverChainId(signed);

        assertTrue(mcr.chainId() == 27);
        assertTrue(mcr.evmChainId() == block.chainid);
    }
}