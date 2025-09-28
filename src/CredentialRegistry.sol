// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title Micro-Credential Registry
/// @notice Stores verified micro-credentials on-chain for lifelong learner profiles.
contract CredentialRegistry {
    // Errors
    error CredentialRegistry__CertificateAlreadyRegistered();
    error CredentialRegistry__InvalidCertificate();

    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    // Data Structures

    struct Certificate {
        bytes32 certHash; //Keccak-256 hash of certificate file pdf/jpg
        bytes32 courseNameHash; // Hash of course name
        bytes32 issuedToHash;   // learner ID
        bytes32 issuerHash; // Hash of institution/issuer ID
        uint256 issuedOn; // Original issue timestamp
    }

    // Each learner has certificates stored by certHash
    struct LearnerProfile {
        bytes32 learnerId; // keccak256 (phone/email/username)
        uint256 certCount; // Number of credentials linked
        mapping(bytes32 => Certificate) certs; // certHash → Certificate
    }

    // Mapping learner → profile
    mapping(bytes32 => LearnerProfile) private learners;

    // Global mapping to ensure certificate uniqueness
    mapping(bytes32 => bool) public existingCerts;

    // ------------------------------
    // Events
    // ------------------------------
    event CertificateAdded(
        bytes32 indexed learnerId, bytes32 indexed certHash, bytes32 indexed issuerIdHash, uint256 timestamp
    );


    /// @notice Add a verified certificate for a learner
    /// @param learnerIdHash keccak256 hash of learner’s unique username/email/etc
    /// @param certHash Keccak-256 hash of certificate file PDF/jpg
    /// @param courseIdHash Hash of course identifier (string → keccak256)
    /// @param issuerIdHash Hash of issuer identifier (string → keccak256)
    /// @param issuedOn Original certificate issue timestamp (off-chain)
    function addCertificate(
        bytes32 learnerIdHash,
        bytes32 certHash,
        bytes32 courseIdHash,
        bytes32 issuerIdHash,
        uint256 issuedOn
    ) external onlyAdmin {
        if (existingCerts[certHash]) {
            revert CredentialRegistry__CertificateAlreadyRegistered();
        }

        LearnerProfile storage profile = learners[learnerIdHash];

        Certificate memory cert = Certificate({
            certHash: certHash,
            courseNameHash: courseIdHash,
            issuerHash: issuerIdHash,
            issuedToHash: learnerIdHash,
            issuedOn: issuedOn
        });

        profile.certs[certHash] = cert;
        profile.certCount += 1;

        existingCerts[certHash] = true;

        emit CertificateAdded(learnerIdHash, certHash, issuerIdHash, block.timestamp);
    }


    /// @notice Get total certificates of a learner
    function getCertCount(bytes32 learnerIdHash) external view returns (uint256) {
        return learners[learnerIdHash].certCount;
    }

    /// @notice Get details of a certificate by certHash
    function verifyCertificate(bytes32 learnerIdHash, bytes32 certHash)
        external
        view
        returns (bytes32, bytes32, bytes32, uint256)
    {
        LearnerProfile storage profile = learners[learnerIdHash];
        Certificate memory cert = profile.certs[certHash];

        if (cert.certHash == 0) {
            revert CredentialRegistry__InvalidCertificate();
        }

        return (cert.certHash, cert.courseNameHash, cert.issuerHash, cert.issuedOn);
    }
}
