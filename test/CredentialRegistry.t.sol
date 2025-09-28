// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/CredentialRegistry.sol";

contract CredentailRegistryTest is Test {
    CredentialRegistry private credentialRegistry;
    address private admin = makeAddr("admin");
    bytes32 private user2 = keccak256(abi.encodePacked("user2"));
    bytes32 private user3 = keccak256(abi.encodePacked("user3"));

    function setUp() public {
        credentialRegistry = new CredentialRegistry(admin);
    }

    function testAddCredential() public {
        bytes32 user1 = keccak256(abi.encodePacked("AL AYAAN ANSARI"));

        bytes memory certData = vm.readFileBinary("test/AL_AYAAN_ANSARI_Certificate.jpg");

        bytes32 certHash = keccak256(certData);
        bytes32 corseNameHash = keccak256(abi.encodePacked("Generative cloud Computing And Generative Ai"));
        bytes32 issuerHash = keccak256(abi.encodePacked("Google Developer student Club"));
        uint256 issueOn = block.timestamp;

        
        vm.expectEmit();

        emit CredentialRegistry.CertificateAdded(user1, certHash, issuerHash, block.timestamp);

        vm.startPrank(admin);
        credentialRegistry.addCertificate(user1, certHash, corseNameHash, issuerHash, issueOn);
        vm.stopPrank();

    }

    function testAddDuplicateCredential() public {
        bytes32 user1 = keccak256(abi.encodePacked("AL AYAAN ANSARI"));

        bytes memory certData = vm.readFileBinary("test/AL_AYAAN_ANSARI_Certificate.jpg");

        bytes32 certHash = keccak256(certData);
        bytes32 corseNameHash = keccak256(abi.encodePacked("Generative cloud Computing And Generative Ai"));
        bytes32 issuerHash = keccak256(abi.encodePacked("Google Developer student Club"));
        uint256 issueOn = block.timestamp;

        
        vm.expectEmit();

        emit CredentialRegistry.CertificateAdded(user1, certHash, issuerHash, block.timestamp);

        vm.startPrank(admin);
        credentialRegistry.addCertificate(user1, certHash, corseNameHash, issuerHash, issueOn);
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectRevert(CredentialRegistry.CredentialRegistry__CertificateAlreadyRegistered.selector);
        credentialRegistry.addCertificate(user1, certHash, corseNameHash, issuerHash, issueOn);
        vm.stopPrank();

    }
}
