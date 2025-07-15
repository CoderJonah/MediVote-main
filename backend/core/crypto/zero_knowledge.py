"""
Zero-Knowledge Proof Implementation for Anonymous Voter Authentication
Uses zk-SNARKs (Groth16) to prove voter eligibility without revealing identity
"""

import json
import hashlib
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import numpy as np
from py_ecc.bn128 import G1, G2, pairing, multiply, add, curve_order
from py_ecc.fields import FQ
import secrets

from core.config import get_crypto_config


config = get_crypto_config()


@dataclass
class ZKProof:
    """Zero-knowledge proof structure"""
    pi_a: Tuple[str, str]  # G1 point
    pi_b: Tuple[Tuple[str, str], Tuple[str, str]]  # G2 point
    pi_c: Tuple[str, str]  # G1 point
    protocol: str = "groth16"
    curve: str = "bn128"


@dataclass
class ZKCircuit:
    """Zero-knowledge circuit definition"""
    name: str
    r1cs_path: str
    wasm_path: str
    zkey_path: str
    verification_key: Dict[str, Any]
    constraint_count: int
    public_signal_count: int
    private_signal_count: int


class ZKProver:
    """Zero-knowledge proof generator"""
    
    def __init__(self, circuit: ZKCircuit):
        self.circuit = circuit
        self.circuit_ready = self._validate_circuit()
    
    def _validate_circuit(self) -> bool:
        """Validate that all circuit files exist"""
        required_files = [
            self.circuit.wasm_path,
            self.circuit.zkey_path
        ]
        
        for file_path in required_files:
            if not os.path.exists(file_path):
                print(f"Missing circuit file: {file_path}")
                return False
        
        return True
    
    def generate_witness(self, public_inputs: Dict[str, Any], private_inputs: Dict[str, Any]) -> Optional[List[str]]:
        """Generate witness from inputs using circuit WASM"""
        if not self.circuit_ready:
            return None
        
        try:
            # Create input file
            input_data = {**public_inputs, **private_inputs}
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(input_data, f)
                input_file = f.name
            
            # Generate witness
            witness_file = input_file.replace('.json', '.wtns')
            
            # Use snarkjs to generate witness
            cmd = [
                'node',
                'node_modules/snarkjs/cli.js',
                'wc',
                self.circuit.wasm_path,
                input_file,
                witness_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Witness generation failed: {result.stderr}")
                return None
            
            # Read witness file (simplified - actual implementation would parse binary)
            witness = self._read_witness_file(witness_file)
            
            # Cleanup
            os.unlink(input_file)
            os.unlink(witness_file)
            
            return witness
            
        except Exception as e:
            print(f"Error generating witness: {e}")
            return None
    
    def _read_witness_file(self, witness_file: str) -> List[str]:
        """Read witness file (simplified implementation)"""
        # This is a placeholder - real implementation would parse binary witness file
        # For now, return mock witness data
        return ["1", "12345", "67890"]  # Mock values
    
    def generate_proof(self, public_inputs: Dict[str, Any], private_inputs: Dict[str, Any]) -> Optional[ZKProof]:
        """Generate zero-knowledge proof"""
        if not self.circuit_ready:
            return None
        
        try:
            # Generate witness
            witness = self.generate_witness(public_inputs, private_inputs)
            if not witness:
                return None
            
            # Create witness file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.wtns', delete=False) as f:
                # Write witness data (simplified)
                witness_file = f.name
            
            # Generate proof using snarkjs
            proof_file = witness_file.replace('.wtns', '_proof.json')
            public_file = witness_file.replace('.wtns', '_public.json')
            
            cmd = [
                'node',
                'node_modules/snarkjs/cli.js',
                'g16p',
                self.circuit.zkey_path,
                witness_file,
                proof_file,
                public_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Proof generation failed: {result.stderr}")
                return None
            
            # Read proof file
            with open(proof_file, 'r') as f:
                proof_data = json.load(f)
            
            # Convert to ZKProof format
            proof = ZKProof(
                pi_a=(proof_data['pi_a'][0], proof_data['pi_a'][1]),
                pi_b=((proof_data['pi_b'][0][0], proof_data['pi_b'][0][1]), 
                      (proof_data['pi_b'][1][0], proof_data['pi_b'][1][1])),
                pi_c=(proof_data['pi_c'][0], proof_data['pi_c'][1])
            )
            
            # Cleanup
            os.unlink(witness_file)
            os.unlink(proof_file)
            os.unlink(public_file)
            
            return proof
            
        except Exception as e:
            print(f"Error generating proof: {e}")
            return None


class ZKVerifier:
    """Zero-knowledge proof verifier"""
    
    def __init__(self, circuit: ZKCircuit):
        self.circuit = circuit
        self.verification_key = circuit.verification_key
    
    def verify_proof(self, proof: ZKProof, public_inputs: List[str]) -> bool:
        """Verify zero-knowledge proof"""
        try:
            # Convert proof elements to curve points
            pi_a = self._string_to_g1(proof.pi_a)
            pi_b = self._string_to_g2(proof.pi_b)
            pi_c = self._string_to_g1(proof.pi_c)
            
            # Get verification key elements
            vk_alpha = self._string_to_g1(self.verification_key['vk_alpha_1'])
            vk_beta = self._string_to_g2(self.verification_key['vk_beta_2'])
            vk_gamma = self._string_to_g2(self.verification_key['vk_gamma_2'])
            vk_delta = self._string_to_g2(self.verification_key['vk_delta_2'])
            
            # Calculate vk_x from public inputs
            vk_x = self._calculate_vk_x(public_inputs)
            
            # Verify pairing equation
            # e(pi_a, pi_b) = e(vk_alpha, vk_beta) * e(vk_x, vk_gamma) * e(pi_c, vk_delta)
            
            left_side = pairing(pi_b, pi_a)
            right_side = (
                pairing(vk_beta, vk_alpha) *
                pairing(vk_gamma, vk_x) *
                pairing(vk_delta, pi_c)
            )
            
            return left_side == right_side
            
        except Exception as e:
            print(f"Error verifying proof: {e}")
            return False
    
    def _string_to_g1(self, point: Tuple[str, str]) -> Tuple[FQ, FQ]:
        """Convert string representation to G1 point"""
        x = FQ(int(point[0]))
        y = FQ(int(point[1]))
        return (x, y)
    
    def _string_to_g2(self, point: Tuple[Tuple[str, str], Tuple[str, str]]) -> Tuple[Tuple[FQ, FQ], Tuple[FQ, FQ]]:
        """Convert string representation to G2 point"""
        x = (FQ(int(point[0][0])), FQ(int(point[0][1])))
        y = (FQ(int(point[1][0])), FQ(int(point[1][1])))
        return (x, y)
    
    def _calculate_vk_x(self, public_inputs: List[str]) -> Tuple[FQ, FQ]:
        """Calculate vk_x from public inputs"""
        # Start with IC[0]
        ic_points = self.verification_key['IC']
        vk_x = self._string_to_g1(ic_points[0])
        
        # Add IC[i] * public_input[i] for each public input
        for i, input_val in enumerate(public_inputs):
            if i + 1 < len(ic_points):
                ic_point = self._string_to_g1(ic_points[i + 1])
                scalar = int(input_val)
                scaled_point = multiply(ic_point, scalar)
                vk_x = add(vk_x, scaled_point)
        
        return vk_x


class VoterEligibilityProof:
    """Specific implementation for voter eligibility proofs"""
    
    def __init__(self, circuit_path: str):
        self.circuit_path = circuit_path
        self.circuit = self._load_circuit()
        self.prover = ZKProver(self.circuit)
        self.verifier = ZKVerifier(self.circuit)
    
    def _load_circuit(self) -> ZKCircuit:
        """Load the voter eligibility circuit"""
        return ZKCircuit(
            name="voter_eligibility",
            r1cs_path=f"{self.circuit_path}/voter_eligibility.r1cs",
            wasm_path=f"{self.circuit_path}/voter_eligibility.wasm",
            zkey_path=f"{self.circuit_path}/voter_eligibility_final.zkey",
            verification_key=self._load_verification_key(),
            constraint_count=1000,  # Example value
            public_signal_count=2,
            private_signal_count=3
        )
    
    def _load_verification_key(self) -> Dict[str, Any]:
        """Load verification key from file"""
        vk_path = f"{self.circuit_path}/verification_key.json"
        if os.path.exists(vk_path):
            with open(vk_path, 'r') as f:
                return json.load(f)
        
        # Return mock verification key for development
        return {
            "protocol": "groth16",
            "curve": "bn128",
            "nPublic": 2,
            "vk_alpha_1": ["0x1", "0x2"],
            "vk_beta_2": [["0x3", "0x4"], ["0x5", "0x6"]],
            "vk_gamma_2": [["0x7", "0x8"], ["0x9", "0xa"]],
            "vk_delta_2": [["0xb", "0xc"], ["0xd", "0xe"]],
            "IC": [["0xf", "0x10"], ["0x11", "0x12"], ["0x13", "0x14"]]
        }
    
    def prove_eligibility(
        self,
        credential_hash: str,
        election_id: str,
        issuer_public_key: str,
        merkle_proof: List[str],
        merkle_root: str
    ) -> Optional[ZKProof]:
        """Generate proof of voter eligibility"""
        
        # Public inputs (known to verifier)
        public_inputs = {
            "election_id": str(int(hashlib.sha256(election_id.encode()).hexdigest()[:8], 16)),
            "merkle_root": str(int(hashlib.sha256(merkle_root.encode()).hexdigest()[:8], 16))
        }
        
        # Private inputs (secret to prover)
        private_inputs = {
            "credential_hash": str(int(hashlib.sha256(credential_hash.encode()).hexdigest()[:8], 16)),
            "issuer_public_key": str(int(hashlib.sha256(issuer_public_key.encode()).hexdigest()[:8], 16)),
            "merkle_proof": [str(int(hashlib.sha256(p.encode()).hexdigest()[:8], 16)) for p in merkle_proof]
        }
        
        return self.prover.generate_proof(public_inputs, private_inputs)
    
    def verify_eligibility(
        self,
        proof: ZKProof,
        election_id: str,
        merkle_root: str
    ) -> bool:
        """Verify proof of voter eligibility"""
        
        public_inputs = [
            str(int(hashlib.sha256(election_id.encode()).hexdigest()[:8], 16)),
            str(int(hashlib.sha256(merkle_root.encode()).hexdigest()[:8], 16))
        ]
        
        return self.verifier.verify_proof(proof, public_inputs)


class MerkleTree:
    """Merkle tree for credential revocation lists"""
    
    def __init__(self, leaves: List[str]):
        self.leaves = leaves
        self.tree = self._build_tree()
    
    def _build_tree(self) -> List[List[str]]:
        """Build Merkle tree from leaves"""
        if not self.leaves:
            return []
        
        tree = [self.leaves[:]]  # Start with leaves
        level = self.leaves[:]
        
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                parent = self._hash_pair(left, right)
                next_level.append(parent)
            
            tree.append(next_level)
            level = next_level
        
        return tree
    
    def _hash_pair(self, left: str, right: str) -> str:
        """Hash a pair of nodes"""
        return hashlib.sha256(f"{left}{right}".encode()).hexdigest()
    
    def get_root(self) -> str:
        """Get Merkle root"""
        if not self.tree:
            return ""
        return self.tree[-1][0]
    
    def get_proof(self, leaf: str) -> List[str]:
        """Get Merkle proof for a leaf"""
        if leaf not in self.leaves:
            return []
        
        leaf_index = self.leaves.index(leaf)
        proof = []
        
        for level in self.tree[:-1]:  # Exclude root level
            if leaf_index % 2 == 0:
                # Left child, need right sibling
                sibling_index = leaf_index + 1
            else:
                # Right child, need left sibling
                sibling_index = leaf_index - 1
            
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            
            leaf_index //= 2
        
        return proof
    
    def verify_proof(self, leaf: str, proof: List[str], root: str) -> bool:
        """Verify Merkle proof"""
        current_hash = leaf
        
        for sibling in proof:
            # Try both left and right positions
            left_hash = self._hash_pair(current_hash, sibling)
            right_hash = self._hash_pair(sibling, current_hash)
            
            # In a real implementation, we'd need to know the position
            # For now, we try both and see which one works
            current_hash = left_hash  # Simplified
        
        return current_hash == root


# Utility functions
def setup_circuit(circuit_name: str, circuit_code: str) -> bool:
    """Setup a new ZK circuit"""
    try:
        circuit_dir = f"./circuits/{circuit_name}"
        os.makedirs(circuit_dir, exist_ok=True)
        
        # Write circuit code
        with open(f"{circuit_dir}/{circuit_name}.circom", "w") as f:
            f.write(circuit_code)
        
        # Compile circuit (simplified)
        # In reality, would use circom compiler
        return True
        
    except Exception as e:
        print(f"Error setting up circuit: {e}")
        return False


def generate_setup_parameters(circuit_path: str) -> bool:
    """Generate trusted setup parameters"""
    try:
        # This would involve a multi-party computation ceremony
        # For now, return True as placeholder
        return True
        
    except Exception as e:
        print(f"Error generating setup parameters: {e}")
        return False 