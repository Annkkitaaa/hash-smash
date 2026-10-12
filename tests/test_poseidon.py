"""Official Orchard Poseidon vectors, pinned deployed constants and domain gates."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from verifier import poseidon
from verifier.hash_functions import digest

FIXTURE = json.loads((Path(__file__).parent / "fixtures/orchard-poseidon-vectors.json").read_text())


def element(encoded: str) -> int:
    """Decode the fixture's canonical 32-byte little-endian hex encoding."""
    return int.from_bytes(bytes.fromhex(encoded), "little")


def reference_prefix(message: bytes, rounds: int) -> bytes:
    """Independent restatement of the round definition, not the code under test.

    Written directly from the deployed schedule: four leading full rounds,
    56 partial rounds, four trailing full rounds, each round adding its
    constants, applying x^5, then multiplying by the MDS matrix. The S-box uses
    pow() rather than the implementation's three-multiplication chain.
    """
    modulus = int(FIXTURE["field_modulus_hex"], 16)
    constants = [[element(value) for value in row] for row in FIXTURE["round_constants"]]
    mds = [[element(value) for value in row] for row in FIXTURE["mds"]]
    capacity = int(FIXTURE["capacity_element_hex"], 16)
    leading = FIXTURE["full_rounds"] // 2
    state = [
        int.from_bytes(message[0:32], "little"),
        int.from_bytes(message[32:64], "little"),
        capacity,
    ]
    for index in range(rounds):
        row = constants[index]
        if index < leading or index >= leading + FIXTURE["partial_rounds"]:
            state = [pow((state[i] + row[i]) % modulus, 5, modulus) for i in range(3)]
        else:
            state = [(state[i] + row[i]) % modulus for i in range(3)]
            state[0] = pow(state[0], 5, modulus)
        state = [sum(mds[i][j] * state[j] for j in range(3)) % modulus for i in range(3)]
    return state[0].to_bytes(32, "little")


class PoseidonVectorTests(unittest.TestCase):
    def test_official_permutation_vectors(self):
        vectors = FIXTURE["permutation_vectors"]
        self.assertEqual(len(vectors), 11)
        for index, vector in enumerate(vectors):
            with self.subTest(vector=index):
                initial = [element(value) for value in vector["initial_state"]]
                expected = [element(value) for value in vector["final_state"]]
                self.assertEqual(poseidon.permutation(initial), expected)

    def test_official_hash_vectors(self):
        vectors = FIXTURE["hash_vectors"]
        self.assertEqual(len(vectors), 11)
        for index, vector in enumerate(vectors):
            with self.subTest(vector=index):
                message = bytes.fromhex(vector["message"])
                self.assertEqual(digest(message, "poseidon", 64).hex(), vector["digest"])

    def test_hash_equals_permuting_the_deployed_initial_state(self):
        # The relation upstream's own orchard_spec_equivalence test asserts.
        for vector in FIXTURE["hash_vectors"]:
            message = bytes.fromhex(vector["message"])
            state = [
                int.from_bytes(message[0:32], "little"),
                int.from_bytes(message[32:64], "little"),
                poseidon.CAPACITY_ELEMENT,
            ]
            self.assertEqual(
                poseidon.permutation(state)[0].to_bytes(32, "little").hex(), vector["digest"]
            )


class PoseidonParameterTests(unittest.TestCase):
    def test_deployed_constants_match_the_pinned_source(self):
        constants = [[element(value) for value in row] for row in FIXTURE["round_constants"]]
        mds = [[element(value) for value in row] for row in FIXTURE["mds"]]
        self.assertEqual(len(constants), 64)
        self.assertEqual(sum(len(row) for row in constants), 192)
        self.assertEqual([list(row) for row in poseidon.ROUND_CONSTANTS], constants)
        self.assertEqual([list(row) for row in poseidon.MDS], mds)
        self.assertEqual(poseidon.MODULUS, int(FIXTURE["field_modulus_hex"], 16))
        self.assertEqual(poseidon.CAPACITY_ELEMENT, int(FIXTURE["capacity_element_hex"], 16))
        self.assertEqual(poseidon.CAPACITY_ELEMENT, 2 << 64)

    def test_every_constant_is_a_canonical_field_element(self):
        for row in poseidon.ROUND_CONSTANTS + poseidon.MDS:
            for value in row:
                self.assertTrue(0 <= value < poseidon.MODULUS)

    def test_round_schedule_matches_the_deployment(self):
        self.assertEqual((poseidon.FULL_ROUNDS, poseidon.PARTIAL_ROUNDS), (8, 56))
        self.assertEqual(poseidon.TOTAL_ROUNDS, 64)
        full = [index for index in range(64) if poseidon.is_full_round(index)]
        self.assertEqual(full, [0, 1, 2, 3, 60, 61, 62, 63])
        self.assertEqual(64 - len(full), 56)

    def test_sbox_is_the_fifth_power(self):
        for value in (0, 1, 2, 7, poseidon.MODULUS - 1, poseidon.ROUND_CONSTANTS[0][0]):
            self.assertEqual(
                poseidon._sbox(value), pow(value, poseidon.SBOX_EXPONENT, poseidon.MODULUS)
            )

    def test_output_space_is_the_field_not_the_encoding(self):
        # 32 bytes of encoding, but the output space is p, about 2^254.
        self.assertLess(poseidon.MODULUS, 1 << 255)
        self.assertGreater(poseidon.MODULUS, 1 << 254)


class PoseidonDomainTests(unittest.TestCase):
    def encode(self, first: int, second: int) -> bytes:
        return first.to_bytes(32, "little") + second.to_bytes(32, "little")

    def test_non_canonical_field_elements_are_rejected(self):
        modulus = poseidon.MODULUS
        for offending in (modulus, modulus + 1, (1 << 256) - 1):
            for position in (0, 1):
                values = [1, 1]
                values[position] = offending
                with self.subTest(offending=hex(offending), position=position):
                    with self.assertRaises(ValueError):
                        digest(self.encode(*values), "poseidon", 64)

    def test_a_shifted_encoding_would_otherwise_be_a_trivial_collision(self):
        # x and x + p reduce to the same field element, so accepting the second
        # encoding would hand out a collision for free. It must be rejected.
        canonical = self.encode(1, 2)
        shifted = self.encode(1 + poseidon.MODULUS, 2)
        self.assertNotEqual(canonical, shifted)
        self.assertEqual(
            int.from_bytes(shifted[0:32], "little") % poseidon.MODULUS,
            int.from_bytes(canonical[0:32], "little") % poseidon.MODULUS,
        )
        self.assertEqual(len(digest(canonical, "poseidon", 64)), 32)
        with self.assertRaises(ValueError):
            digest(shifted, "poseidon", 64)

    def test_wrong_message_lengths_are_rejected(self):
        for length in (0, 1, 31, 32, 33, 63, 65, 96, 128):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    digest(bytes(length), "poseidon", 64)

    def test_non_bytes_messages_are_rejected(self):
        for data in (None, "a" * 64, bytearray(64), [0] * 64, memoryview(bytes(64))):
            with self.subTest(data=type(data).__name__):
                with self.assertRaises(ValueError):
                    digest(data, "poseidon", 64)

    def test_invalid_round_counts_fail_closed(self):
        message = self.encode(1, 2)
        for rounds in (0, -1, 65, 100, True, 1.0, "1", None):
            with self.subTest(rounds=rounds):
                with self.assertRaises(ValueError):
                    digest(message, "poseidon", rounds)

    def test_permutation_rejects_malformed_states(self):
        for state in ([1, 2], [1, 2, 3, 4], [1, 2, poseidon.MODULUS], [1, 2, -1], [1, 2, True]):
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    poseidon.permutation(state)


class PoseidonPrefixRoundTests(unittest.TestCase):
    MESSAGE = (7).to_bytes(32, "little") + (11).to_bytes(32, "little")

    def test_rounds_one_and_two_match_an_independent_reference(self):
        for rounds in (1, 2):
            with self.subTest(rounds=rounds):
                self.assertEqual(
                    digest(self.MESSAGE, "poseidon", rounds), reference_prefix(self.MESSAGE, rounds)
                )

    def test_every_prefix_matches_the_independent_reference(self):
        # The implementation must already support any prefix from 1 to 64,
        # so a later round pair needs no code change.
        for rounds in range(1, 65):
            with self.subTest(rounds=rounds):
                self.assertEqual(
                    digest(self.MESSAGE, "poseidon", rounds), reference_prefix(self.MESSAGE, rounds)
                )

    def test_prefixes_are_distinct_from_each_other_and_from_the_deployment(self):
        digests = {rounds: digest(self.MESSAGE, "poseidon", rounds) for rounds in (1, 2, 64)}
        self.assertNotEqual(digests[1], digests[2])
        self.assertNotEqual(digests[1], digests[64])
        self.assertNotEqual(digests[2], digests[64])
        self.assertEqual({len(value) for value in digests.values()}, {32})

    def test_the_first_two_rounds_are_full_rounds(self):
        # Rounds 1 and 2 apply the S-box to all three elements.
        self.assertTrue(poseidon.is_full_round(0))
        self.assertTrue(poseidon.is_full_round(1))


class PoseidonNegativeControlTests(unittest.TestCase):
    """A wrong constant, capacity or round count must break the official vectors."""

    def official_hash_passes(self) -> bool:
        return all(
            digest(bytes.fromhex(vector["message"]), "poseidon", 64).hex() == vector["digest"]
            for vector in FIXTURE["hash_vectors"]
        )

    def test_controls_are_measured_against_a_passing_baseline(self):
        self.assertTrue(self.official_hash_passes())

    def test_a_changed_round_constant_breaks_the_vectors(self):
        mutated = list(poseidon.ROUND_CONSTANTS)
        row = list(mutated[0])
        row[0] = (row[0] + 1) % poseidon.MODULUS
        mutated[0] = tuple(row)
        with patch.object(poseidon, "ROUND_CONSTANTS", tuple(mutated)):
            self.assertFalse(self.official_hash_passes())

    def test_a_changed_mds_entry_breaks_the_vectors(self):
        mutated = [list(row) for row in poseidon.MDS]
        mutated[0][0] = (mutated[0][0] + 1) % poseidon.MODULUS
        with patch.object(poseidon, "MDS", tuple(tuple(row) for row in mutated)):
            self.assertFalse(self.official_hash_passes())

    def test_a_wrong_capacity_element_breaks_the_vectors(self):
        for wrong in (0, 1, 1 << 64, 3 << 64, 2 << 65):
            with self.subTest(capacity=hex(wrong)):
                with patch.object(poseidon, "CAPACITY_ELEMENT", wrong):
                    self.assertFalse(self.official_hash_passes())

    def test_a_wrong_round_count_breaks_the_vectors(self):
        for rounds in (1, 2, 32, 63):
            with self.subTest(rounds=rounds):
                self.assertFalse(
                    any(
                        digest(bytes.fromhex(vector["message"]), "poseidon", rounds).hex()
                        == vector["digest"]
                        for vector in FIXTURE["hash_vectors"]
                    )
                )

    def test_swapping_the_partial_round_schedule_breaks_the_vectors(self):
        # Applying the S-box to every element in a partial round is the most
        # likely transcription error; it must not reproduce the vectors.
        with patch.object(poseidon, "PARTIAL_ROUNDS", 0), patch.object(poseidon, "FULL_ROUNDS", 64):
            self.assertFalse(self.official_hash_passes())


if __name__ == "__main__":
    unittest.main()
