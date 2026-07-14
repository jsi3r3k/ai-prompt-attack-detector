import unittest

from detectors.ai_common import normalize_ai_result


class TestAIResultNormalization(unittest.TestCase):
    def test_attack_score_from_ten_point_scale_is_normalized(self):
        provider_result = {
            "status": "completed",
            "is_attack": True,
            "risk_score": 9,
            "categories": [
                "override previous instructions",
                "bypass safety rules",
            ],
            "verdict": "block",
            "analysis": (
                "The request attempts to bypass safety rules."
            ),
        }

        result = normalize_ai_result(
            provider_result,
            detection_method="gemini_api",
        )

        self.assertEqual(result["risk_score"], 90)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertFalse(result["safe_to_process"])
        self.assertIn(
            "instruction_override",
            result["categories"],
        )


if __name__ == "__main__":
    unittest.main()