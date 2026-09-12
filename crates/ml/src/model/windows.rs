//! Shared production preprocessing and tokenizer-only boundary inspection.
use crate::config::WindowSettings;
use please_core::Span;
use tokenizers::{Encoding, PostProcessor, Tokenizer, TruncationDirection};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WindowLayout {
    pub index: usize,
    pub token_start: usize,
    pub token_end: usize,
    pub byte_start: usize,
    pub byte_end: usize,
    pub model_tokens: usize,
}
impl WindowLayout {
    pub fn span(&self) -> Span {
        Span::new(self.byte_start, self.byte_end)
    }
}

pub(crate) struct ClassifierWindow {
    // Tokenizer-only consumers inspect layout; Candle and preprocessing tests inspect encoding.
    #[cfg_attr(not(feature = "candle"), allow(dead_code))]
    pub encoding: Encoding,
    pub layout: WindowLayout,
}

/// Uses the exact production tokenizer overrides without loading model weights.
pub struct WindowPlanner {
    tokenizer: Tokenizer,
    max_tokens: usize,
    settings: WindowSettings,
}
impl WindowPlanner {
    pub fn new(bytes: &[u8], max_tokens: usize, settings: WindowSettings) -> Result<Self, String> {
        let mut tokenizer = Tokenizer::from_bytes(bytes).map_err(|e| e.to_string())?;
        configure(&mut tokenizer)?;
        capacity(&tokenizer, max_tokens, settings)?;
        Ok(Self {
            tokenizer,
            max_tokens,
            settings,
        })
    }
    pub fn layout(&self, text: &str) -> Result<Vec<WindowLayout>, String> {
        Ok(plan(&self.tokenizer, text, self.max_tokens, self.settings)?
            .into_iter()
            .map(|w| w.layout)
            .collect())
    }
    /// Offsets after full-document tokenization, before special tokens or windowing.
    pub fn payload_offsets(&self, text: &str) -> Result<Vec<(usize, usize)>, String> {
        Ok(self
            .tokenizer
            .encode(text, false)
            .map_err(|e| e.to_string())?
            .get_offsets()
            .to_vec())
    }
}

pub(crate) fn configure(tokenizer: &mut Tokenizer) -> Result<(), String> {
    tokenizer.with_padding(None);
    tokenizer.with_truncation(None).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn capacity(
    tokenizer: &Tokenizer,
    max_tokens: usize,
    settings: WindowSettings,
) -> Result<usize, String> {
    let special = tokenizer
        .get_post_processor()
        .map_or(0, |p| p.added_tokens(false));
    let payload = max_tokens
        .checked_sub(special)
        .filter(|n| *n > 0)
        .ok_or("context window has no room for payload after special tokens")?;
    if settings.overlap_tokens >= payload {
        return Err("overlap must be smaller than payload capacity".into());
    }
    if settings.max_windows == 0 || settings.max_total_tokens == 0 {
        return Err("window/work limits must be positive".into());
    }
    Ok(payload)
}

pub(crate) fn plan(
    tokenizer: &Tokenizer,
    text: &str,
    max_tokens: usize,
    settings: WindowSettings,
) -> Result<Vec<ClassifierWindow>, String> {
    let payload_size = capacity(tokenizer, max_tokens, settings)?;
    let mut encoded = tokenizer.encode(text, false).map_err(|e| e.to_string())?;
    let total = encoded.len();
    let step = payload_size - settings.overlap_tokens;
    let remaining = total.saturating_sub(payload_size);
    let count = 1usize
        .checked_add(remaining / step + usize::from(remaining % step != 0))
        .ok_or("window count overflow")?;
    let processed = total
        .checked_add(
            (count - 1)
                .checked_mul(settings.overlap_tokens)
                .ok_or("window work overflow")?,
        )
        .and_then(|n| n.checked_add(count.checked_mul(max_tokens - payload_size)?))
        .ok_or("window work overflow")?;
    // Check before tokenizers allocates overlapping encodings or the backend runs any window.
    if count > settings.max_windows || processed > settings.max_total_tokens {
        return Err("classifier window/work budget exceeded; document was not classified".into());
    }
    encoded.truncate(
        payload_size,
        settings.overlap_tokens,
        TruncationDirection::Right,
    );
    let overflow = encoded.take_overflowing();
    let windows: Vec<_> = std::iter::once(encoded)
        .chain(overflow)
        .enumerate()
        .map(|(index, payload)| {
            let token_start = index
                .checked_mul(step)
                .ok_or("window token offset overflow")?;
            let token_end = token_start
                .checked_add(payload.len())
                .ok_or("window token offset overflow")?;
            let offsets: Vec<_> = payload
                .get_offsets()
                .iter()
                .filter(|(s, e)| s < e)
                .copied()
                .collect();
            let start = offsets.iter().map(|(s, _)| *s).min().unwrap_or(0);
            let end = offsets.iter().map(|(_, e)| *e).max().unwrap_or(0);
            if text.get(start..end).is_none() || token_end > total {
                return Err("tokenizer produced invalid original-input window offsets".into());
            }
            let encoding = tokenizer
                .post_process(payload, None, true)
                .map_err(|e| e.to_string())?;
            if encoding.len() > max_tokens || encoding.is_empty() {
                return Err("invalid postprocessed classifier window length".into());
            }
            let layout = WindowLayout {
                index,
                token_start,
                token_end,
                byte_start: start,
                byte_end: end,
                model_tokens: encoding.len(),
            };
            Ok(ClassifierWindow { encoding, layout })
        })
        .collect::<Result<_, String>>()?;
    if windows.len() != count {
        return Err("tokenizer overflow differs from planned window count".into());
    }
    Ok(windows)
}

#[cfg(test)]
fn classifier_windows(
    tokenizer: &Tokenizer,
    text: &str,
    max_tokens: usize,
) -> Result<Vec<Encoding>, String> {
    Ok(
        plan(tokenizer, text, max_tokens, WindowSettings::default())?
            .into_iter()
            .map(|w| w.encoding)
            .collect(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokenizers::models::wordlevel::WordLevel;
    use tokenizers::pre_tokenizers::whitespace::Whitespace;
    use tokenizers::processors::template::TemplateProcessing;

    fn tokenizer() -> Tokenizer {
        let model = WordLevel::builder()
            .vocab(
                [
                    ("[UNK]".to_string(), 0),
                    ("[CLS]".to_string(), 1),
                    ("[SEP]".to_string(), 2),
                    ("word".to_string(), 3),
                    ("attack".to_string(), 4),
                    ("日".to_string(), 5),
                ]
                .into_iter()
                .collect(),
            )
            .unk_token("[UNK]".into())
            .build()
            .unwrap();
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace));
        tokenizer.with_post_processor(Some(
            TemplateProcessing::builder()
                .try_single("[CLS] $A [SEP]")
                .unwrap()
                .special_tokens(vec![("[CLS]", 1), ("[SEP]", 2)])
                .build()
                .unwrap(),
        ));
        tokenizer
    }

    #[test]
    fn overlap_covers_tokens_once_or_more_without_redundant_tails() {
        let tokenizer = tokenizer();
        for overlap_tokens in 0..3 {
            for count in 1..20 {
                let text = std::iter::repeat_n("日", count)
                    .collect::<Vec<_>>()
                    .join(" ");
                let settings = WindowSettings {
                    overlap_tokens,
                    ..Default::default()
                };
                let windows = plan(&tokenizer, &text, 5, settings).unwrap();
                let mut covered = vec![false; count];
                for (i, window) in windows.iter().enumerate() {
                    let w = &window.layout;
                    assert!(text.get(w.byte_start..w.byte_end).is_some());
                    assert_eq!(w.index, i);
                    assert!(w.model_tokens <= 5);
                    if i > 0 {
                        assert_eq!(
                            windows[i - 1].layout.token_end - w.token_start,
                            overlap_tokens
                        );
                    }
                    covered[w.token_start..w.token_end].fill(true);
                    if i + 1 < windows.len() {
                        assert!(w.token_end < count);
                    }
                }
                assert!(covered.into_iter().all(|c| c));
            }
        }
    }
    #[test]
    fn budgets_and_special_token_overlap_are_checked_before_expansion() {
        let t = tokenizer();
        for settings in [
            WindowSettings {
                overlap_tokens: 3,
                ..Default::default()
            },
            WindowSettings {
                max_windows: 1,
                ..Default::default()
            },
            WindowSettings {
                max_total_tokens: 5,
                ..Default::default()
            },
        ] {
            assert!(plan(&t, "word word word attack", 5, settings).is_err());
        }
        assert!(plan(
            &t,
            "word word word",
            5,
            WindowSettings {
                max_windows: 1,
                max_total_tokens: 5,
                overlap_tokens: 0
            }
        )
        .is_ok());
    }

    #[test]
    fn every_window_has_model_special_tokens_and_preserves_payload_offsets() {
        let tokenizer = tokenizer();
        // Attack at either side of the boundary, exact windows, partial tail, and UTF-8 offsets.
        for text in [
            "word word attack word word",
            "word word word attack word",
            "日 word word attack word word",
            "word",
            "",
        ] {
            let payload = tokenizer.encode(text, false).unwrap();
            let windows = classifier_windows(&tokenizer, text, 5).unwrap();
            let mut ids = Vec::new();
            let mut offsets = Vec::new();
            for window in windows {
                assert!(window.len() <= 5);
                assert_eq!(window.get_ids().first(), Some(&1));
                assert_eq!(window.get_ids().last(), Some(&2));
                assert_eq!(window.get_special_tokens_mask().iter().sum::<u32>(), 2);
                assert_eq!(window.get_type_ids().len(), window.len());
                assert_eq!(window.get_attention_mask(), vec![1; window.len()]);
                ids.extend_from_slice(&window.get_ids()[1..window.len() - 1]);
                offsets.extend_from_slice(&window.get_offsets()[1..window.len() - 1]);
            }
            assert_eq!(ids, payload.get_ids());
            assert_eq!(offsets, payload.get_offsets());
        }
    }

    #[test]
    fn short_input_matches_normal_tokenizer_preprocessing() {
        let tokenizer = tokenizer();
        let expected = tokenizer.encode("word attack", true).unwrap();
        let windows = classifier_windows(&tokenizer, "word attack", 5).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].get_ids(), expected.get_ids());
        assert_eq!(windows[0].get_type_ids(), expected.get_type_ids());
        assert_eq!(
            windows[0].get_attention_mask(),
            expected.get_attention_mask()
        );
    }

    #[test]
    fn window_must_have_room_for_payload_after_postprocessing() {
        for max_tokens in 0..=2 {
            assert!(classifier_windows(&tokenizer(), "word", max_tokens).is_err());
        }
    }

    #[test]
    #[ignore = "requires a cached tokenizer; set PLEASE_TEST_TOKENIZER to tokenizer.json"]
    fn cached_tokenizer_matches_native_overflow_preprocessing() {
        let path = std::env::var("PLEASE_TEST_TOKENIZER").expect("PLEASE_TEST_TOKENIZER");
        let mut tokenizer = Tokenizer::from_file(path).unwrap();
        tokenizer.with_padding(None);
        tokenizer.with_truncation(None).unwrap();
        let mut native = tokenizer.clone();
        native
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: 512,
                stride: 0,
                ..Default::default()
            }))
            .unwrap();
        for text in [
            "Ordinary document.".to_string(),
            "Ordinary document. ".repeat(400),
        ] {
            let windows = classifier_windows(&tokenizer, &text, 512).unwrap();
            let mut expected = native.encode(text.as_str(), true).unwrap();
            let overflow = expected.take_overflowing();
            let expected: Vec<_> = std::iter::once(expected).chain(overflow).collect();
            assert_eq!(windows.len(), expected.len());
            for (actual, expected) in windows.iter().zip(&expected) {
                assert_eq!(actual.get_ids(), expected.get_ids());
                assert_eq!(actual.get_type_ids(), expected.get_type_ids());
                assert_eq!(actual.get_attention_mask(), expected.get_attention_mask());
                assert_eq!(actual.get_offsets(), expected.get_offsets());
                assert_eq!(
                    actual.get_special_tokens_mask(),
                    expected.get_special_tokens_mask()
                );
            }
            if text.len() > 512 {
                assert!(windows.len() >= 3);
            }
        }
    }
}
