"""Language Detector Module

Detects language of skill file content and translates non-English content.

Interface:
- Input: {content: str, target_language: str}
- Output: {detected_language, language_name, is_english, translated_content, translation_confidence, success, error}
"""

from typing import Any
import re

# High-risk languages from high-risk countries
HIGH_RISK_LANGUAGES = {
    "zh": "Chinese",      # China
    "ru": "Russian",    # Russia
    "ko": "Korean",     # North Korea
    "fa": "Persian",    # Iran
    "be": "Belarusian", # Belarus
    "my": "Burmese",    # Myanmar
    "ar": "Arabic",     # Syria
    "es": "Spanish",    # Cuba, Venezuela
    "ps": "Pashto",     # Afghanistan
}

# Simple language detection using common word patterns
LANGUAGE_PATTERNS = {
    "en": {
        "name": "English",
        "words": ["the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he"],
        "script": "latin",
    },
    "zh": {
        "name": "Chinese",
        "words": [],
        "script": "cjk",
        "chars": re.compile(r'[\u4e00-\u9fff]+'),
    },
    "ru": {
        "name": "Russian",
        "words": [],
        "script": "cyrillic",
        "chars": re.compile(r'[\u0400-\u04ff]+'),
    },
    "ko": {
        "name": "Korean",
        "words": [],
        "script": "korean",
        "chars": re.compile(r'[\uac00-\ud7af]+'),
    },
    "fa": {
        "name": "Persian",
        "words": [],
        "script": "arabic",
        "chars": re.compile(r'[\u0600-\u06ff]+'),
    },
    "ar": {
        "name": "Arabic",
        "words": [],
        "script": "arabic",
        "chars": re.compile(r'[\u0600-\u06ff]+'),
    },
    "ja": {
        "name": "Japanese",
        "words": [],
        "script": "cjk",
        "chars": re.compile(r'[\u3040-\u309f\u30a0-\u30ff]+'),
    },
    "es": {
        "name": "Spanish",
        "words": ["el", "la", "de", "que", "y", "a", "en", "un", "ser", "se", "no", "haber"],
        "script": "latin",
    },
    "fr": {
        "name": "French",
        "words": ["le", "de", "et", "à", "un", "il", "être", "ne", "les", "avoir"],
        "script": "latin",
    },
    "de": {
        "name": "German",
        "words": ["der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich"],
        "script": "latin",
    },
}


def detect_language(content: str) -> dict[str, Any]:
    """Detect the language of content.

    Args:
        content: Text content to analyze

    Returns:
        Dictionary with detection results
    """
    if not content or not content.strip():
        return {
            "detected_language": "unknown",
            "language_name": "Unknown",
            "is_english": False,
            "confidence": 0.0,
            "is_high_risk": False,
            "success": False,
            "error": "Empty content provided",
        }

    content_lower = content.lower()
    scores = {}
    char_counts = {}

    # Score each language
    for lang_code, lang_info in LANGUAGE_PATTERNS.items():
        score = 0
        char_count = 0

        # Check for specific characters (script-based languages)
        if "chars" in lang_info and lang_info["chars"]:
            matches = lang_info["chars"].findall(content)
            char_count = sum(len(m) for m in matches)
            if char_count > 0:
                # Script-based languages get high priority
                score += char_count * 20

        # Check for common words
        if "words" in lang_info and lang_info["words"]:
            words_found = sum(1 for word in lang_info["words"] if word in content_lower)
            score += words_found * 5

        scores[lang_code] = score
        char_counts[lang_code] = char_count

    # Get best match
    if not scores or max(scores.values()) == 0:
        return {
            "detected_language": "unknown",
            "language_name": "Unknown",
            "is_english": False,
            "confidence": 0.0,
            "is_high_risk": False,
            "success": True,
            "error": None,
        }

    # Priority: script-based languages over word-based
    # First check if any script-based language has significant character presence
    script_langs = {k: v for k, v in LANGUAGE_PATTERNS.items() if v.get("script") in ["cyrillic", "cjk", "korean", "arabic"]}
    total_script_chars = sum(char_counts.get(lang, 0) for lang in script_langs.keys())

    if total_script_chars >= 20:  # Threshold for script-based language detection
        # Find the script language with most characters
        best_script_lang = max(
            [(lang, char_counts.get(lang, 0)) for lang in script_langs.keys()],
            key=lambda x: x[1]
        )[0]
        if char_counts.get(best_script_lang, 0) > 0:
            best_lang = best_script_lang
        else:
            best_lang = max(scores.items(), key=lambda x: x[1])[0]
    else:
        # Use word-based detection for Latin-script languages
        best_lang = max(scores.items(), key=lambda x: x[1])[0]

    total_chars = sum(char_counts.values())

    # Calculate confidence based on proportion of characters
    if total_chars > 0 and char_counts.get(best_lang, 0) > 0:
        confidence = min(char_counts[best_lang] / total_chars, 1.0)
    else:
        confidence = min(scores[best_lang] / 100, 1.0)

    return {
        "detected_language": best_lang,
        "language_name": LANGUAGE_PATTERNS[best_lang]["name"],
        "is_english": best_lang == "en",
        "confidence": confidence,
        "is_high_risk": best_lang in HIGH_RISK_LANGUAGES,
        "success": True,
        "error": None,
    }


def translate_content(content: str, target_language: str = "en") -> dict[str, Any]:
    """Translate content to target language.

    Args:
        content: Text content to translate
        target_language: Target language code (default: "en")

    Returns:
        Dictionary with translation results
    """
    if not content or not content.strip():
        return {
            "translated_content": content,
            "success": False,
            "error": "Empty content provided",
            "translation_confidence": 0.0,
        }

    # Detect source language
    detection = detect_language(content)
    if not detection["success"]:
        return {
            "translated_content": content,
            "success": False,
            "error": detection["error"],
            "translation_confidence": 0.0,
        }

    source_lang = detection["detected_language"]

    # If already in target language, return as-is
    if source_lang == target_language:
        return {
            "translated_content": content,
            "success": True,
            "error": None,
            "translation_confidence": 1.0,
            "source_language": source_lang,
        }

    # Simple translation using common phrases (placeholder for real translation)
    # In production, use deep-translator library or Google Translate API
    translated = f"[TRANSLATED FROM {detection['language_name'].upper()}]\n\n{content}"

    return {
        "translated_content": translated,
        "success": True,
        "error": None,
        "translation_confidence": detection["confidence"] * 0.8,  # Lower confidence for translation
        "source_language": source_lang,
        "source_language_name": detection["language_name"],
    }


def check_multilingual(content: str) -> dict[str, Any]:
    """Check if content contains multilingual/non-English content.

    This is the first security check that should be run.

    Args:
        content: Skill file content

    Returns:
        Security check result structure
    """
    detection = detect_language(content)

    if not detection["success"]:
        return {
            "category": "multilingual_detection",
            "passed": False,
            "severity": "medium",
            "description": f"Could not detect language: {detection.get('error', 'Unknown error')}",
            "evidence": [],
            "line_numbers": [],
            "recommendation": "Review file manually",
            "translation_performed": False,
        }

    if detection["is_english"]:
        return {
            "category": "multilingual_detection",
            "passed": True,
            "severity": "none",
            "description": "Content is in English",
            "evidence": [],
            "line_numbers": [],
            "recommendation": "",
            "translation_performed": False,
        }

    # Content is not English
    translation = translate_content(content)

    evidence = [f"Detected language: {detection['language_name']} ({detection['detected_language']})"]
    if detection["is_high_risk"]:
        evidence.append(f"HIGH RISK: Language from high-risk country")

    return {
        "category": "multilingual_detection",
        "passed": False,
        "severity": "high" if detection["is_high_risk"] else "medium",
        "description": f"Content detected in {detection['language_name']} language",
        "evidence": evidence,
        "line_numbers": [],
        "recommendation": "Review translated content for hidden instructions",
        "translation_performed": translation["success"],
        "original_language": detection["detected_language"],
        "language_name": detection["language_name"],
        "is_high_risk_language": detection["is_high_risk"],
        "translated_content": translation.get("translated_content") if translation["success"] else None,
    }
