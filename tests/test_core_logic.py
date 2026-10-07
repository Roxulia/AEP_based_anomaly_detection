import math
import unittest

from src.aep_anomaly import AEPDetector, InformationScoreDensity, MarkovModel


class MarkovModelTests(unittest.TestCase):
    def test_deterministic_alternating_chain_has_near_zero_entropy_rate(self) -> None:
        model = MarkovModel(smoothing=1e-6).fit([["A", "B", "A", "B"]])
        self.assertAlmostEqual(model.entropy_rate_bits, 0.0, places=4)

    def test_uniform_two_state_chain_has_one_bit_entropy_rate(self) -> None:
        model = MarkovModel(smoothing=0.5).fit(
            [["A", "A"], ["A", "B"], ["B", "A"], ["B", "B"]]
        )
        self.assertAlmostEqual(model.entropy_rate_bits, 1.0, places=12)
        self.assertAlmostEqual(sum(model.stationary_distribution.values()), 1.0)

    def test_less_likely_sequence_has_higher_information_score(self) -> None:
        model = MarkovModel(smoothing=0.1).fit([["A", "A", "A", "B", "A", "A"]])
        common = model.score_sequence(["A", "A", "A"])
        rare = model.score_sequence(["A", "B", "B"])
        self.assertGreater(rare.information_score, common.information_score)
        self.assertEqual(len(rare.transition_probabilities), 2)
        self.assertTrue(rare.least_probable_transitions)

    def test_unknown_state_fails_explicitly(self) -> None:
        model = MarkovModel().fit([["known"]])
        with self.assertRaisesRegex(ValueError, "not observed during fit"):
            model.score_sequence(["unknown"])


class AEPDetectorTests(unittest.TestCase):
    def test_deviation_and_validation_quantile_threshold(self) -> None:
        detector = AEPDetector(quantile=0.5)
        threshold = detector.fit_threshold([1.0, 2.0, 3.0], entropy_rate=2.0)
        self.assertEqual(threshold, 1.0)
        typical = detector.score(2.5, entropy_rate=2.0)
        atypical = detector.score(4.0, entropy_rate=2.0)
        self.assertEqual(typical.aep_deviation, 0.5)
        self.assertFalse(typical.anomalous)
        self.assertTrue(atypical.anomalous)

    def test_non_finite_validation_score_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite"):
            AEPDetector().fit_threshold([math.inf], entropy_rate=1.0)


class InformationScoreDensityTests(unittest.TestCase):
    def test_kde_gives_higher_anomaly_score_to_low_density_value(self) -> None:
        density = InformationScoreDensity().fit([-1.0, -0.5, 0.0, 0.5, 1.0])
        density.fit_threshold([-0.8, -0.2, 0.2, 0.8])
        central = density.score(0.0)
        tail = density.score(5.0)
        self.assertTrue(math.isfinite(central.density))
        self.assertTrue(math.isfinite(tail.anomaly_score))
        self.assertGreater(tail.anomaly_score, central.anomaly_score)
        self.assertIsInstance(tail.anomalous, bool)

    def test_kde_rejects_constant_or_insufficient_training_data(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least two"):
            InformationScoreDensity().fit([1.0])
        with self.assertRaisesRegex(ValueError, "non-zero variance"):
            InformationScoreDensity().fit([1.0, 1.0])


if __name__ == "__main__":
    unittest.main()
