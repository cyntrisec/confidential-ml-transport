use std::path::Path;

use anyhow::{Context, Result};
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use tokenizers::Tokenizer;

pub struct EmbeddingModel {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

impl EmbeddingModel {
    /// Load MiniLM-L6-v2 from a directory containing model.safetensors,
    /// tokenizer.json, and config.json.
    pub fn load(model_dir: &Path) -> Result<Self> {
        let device = Device::Cpu;

        let config_path = model_dir.join("config.json");
        let config: Config = serde_json::from_str(
            &std::fs::read_to_string(&config_path)
                .with_context(|| format!("reading {}", config_path.display()))?,
        )
        .context("parsing config.json")?;

        let tokenizer_path = model_dir.join("tokenizer.json");
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("loading tokenizer: {e}"))?;

        let weights_path = model_dir.join("model.safetensors");
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[&weights_path], DTYPE, &device)
                .context("loading model weights")?
        };

        let model = BertModel::load(vb, &config).context("building BertModel")?;

        tracing::info!(
            "loaded model from {} (hidden_size={})",
            model_dir.display(),
            config.hidden_size
        );

        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }

    /// Encode text into a sentence embedding vector.
    /// Returns the raw f32 bytes suitable for sending as a tensor.
    pub fn encode(&self, text: &str) -> Result<Vec<f32>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("tokenization failed: {e}"))?;

        let ids = encoding.get_ids();
        let type_ids = encoding.get_type_ids();
        let attention_mask = encoding.get_attention_mask();

        let input_ids = Tensor::new(ids, &self.device)?.unsqueeze(0)?;
        let token_type_ids = Tensor::new(type_ids, &self.device)?.unsqueeze(0)?;
        let mask = Tensor::new(attention_mask, &self.device)?.unsqueeze(0)?;

        let embeddings = self
            .model
            .forward(&input_ids, &token_type_ids, Some(&mask))?;

        // Mean pooling: sum token embeddings weighted by attention mask, divide by mask sum
        let mask_f = mask.to_dtype(DTYPE)?.unsqueeze(2)?;
        let sum_mask = mask_f.sum(1)?;
        let pooled = embeddings
            .broadcast_mul(&mask_f)?
            .sum(1)?
            .broadcast_div(&sum_mask)?;

        // L2 normalize
        let norm = pooled.sqr()?.sum_keepdim(1)?.sqrt()?;
        let normalized = pooled.broadcast_div(&norm)?;

        let embedding: Vec<f32> = normalized.squeeze(0)?.to_vec1()?;
        Ok(embedding)
    }

    /// Return the embedding dimensionality (384 for MiniLM-L6-v2).
    pub fn dim(&self) -> usize {
        384
    }
}
