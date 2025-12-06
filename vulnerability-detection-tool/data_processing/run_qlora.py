# fine_tuning/run_qlora_optimized.py
import torch
import pandas as pd
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainerCallback,
    logging
)
from peft import LoraConfig, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig
import os

# --- Configuration ---
base_model_name = "Qwen/Qwen2.5-Coder-7B-Instruct"
new_model_name = "qwen2.5-vuln-detector-v1"
dataset_path = "/workspace/vulnerability-detection-tool/datasets/processed/final_complete_dataset.parquet"
output_dir = f"./results/{new_model_name}"

# Set logging
logging.set_verbosity_info()

# --- 1. Data Loading and Optimization ---
print("=" * 80)
print("--- Loading Final, Complete Dataset ---")
df = pd.read_parquet(dataset_path)
print(f"Initial dataset size: {len(df)} samples")

# --- SPEEDUP FIX #1: Use smaller, high-quality random sample ---
SAMPLE_SIZE = 40000  # Reduced from 160K for faster initial training
if len(df) > SAMPLE_SIZE:
    print(f"--- Sub-sampling dataset from {len(df)} to {SAMPLE_SIZE} samples for faster training ---")
    df = df.sample(n=SAMPLE_SIZE, random_state=42)
    print(f"New dataset size: {len(df)} samples")

# Filter out extremely long code samples
MAX_CHARS = 120000
initial_count = len(df)
df = df[df['code'].str.len() < MAX_CHARS]
filtered_count = initial_count - len(df)
print(f"--- Filtered out {filtered_count} samples with excessive length (>{MAX_CHARS} chars) ---")
print(f"Final dataset size: {len(df)} samples")

# --- 2. Prompt Engineering ---
def create_prompt(sample):
    """Create a formatted prompt for vulnerability detection"""
    vulnerability_status = "Vulnerable" if sample['is_vulnerable'] == 1 else "Not Vulnerable"
    language = sample.get('language', 'c')
    
    # Add CWE information if available
    cwe_info = ""
    if pd.notna(sample.get('cwe')) and sample['cwe'] != 'N/A':
        cwe_info = f"The CWE is {sample['cwe']}."
    
    prompt = f"""<|im_start|>system
You are an expert security analyst. Analyze the following code snippet for vulnerabilities.
Respond with "Vulnerable" if it contains a security flaw, or "Not Vulnerable" if it is secure.
Provide the CWE ID if the code is vulnerable.
<|im_end|>
<|im_start|>user
Analyze this {language} code:

{sample['code']}
<|im_end|>
<|im_start|>assistant
{vulnerability_status}
{cwe_info}
<|im_end|>"""
    
    return prompt

# Format dataset for training
def format_for_training(sample):
    """Format sample into training text"""
    text = create_prompt(sample)
    return {"text": text}

print("\n--- Formatting Dataset ---")
dataset = Dataset.from_pandas(df)
dataset = dataset.map(
    format_for_training, 
    remove_columns=dataset.column_names,
    desc="Formatting samples"
)
print(f"Dataset formatted: {len(dataset)} samples")

# --- 3. Model Configuration ---
print("\n" + "=" * 80)
print("--- Setting up Model Configuration ---")

# --- SPEEDUP FIX #2: Optimized BitsAndBytes Configuration ---
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,  # Better than float16 on RTX 5090
    bnb_4bit_use_double_quant=True,         # Nested quantization
)
print("✓ BitsAndBytes config created (4-bit quantization with bfloat16)")

# --- 4. Load Model and Tokenizer ---
print("\n--- Loading Model ---")
model = AutoModelForCausalLM.from_pretrained(
    base_model_name,
    quantization_config=bnb_config,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    # attn_implementation="flash_attention_2",  # Uncomment if flash-attn installed
)
print(f"✓ Model loaded: {base_model_name}")

# Prepare model for k-bit training
model = prepare_model_for_kbit_training(model)
print("✓ Model prepared for k-bit training")

print("\n--- Loading Tokenizer ---")
tokenizer = AutoTokenizer.from_pretrained(
    base_model_name,
    trust_remote_code=True,
    padding_side="right",  # Required for decoder-only models
)

# Set padding token if not set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.pad_token_id = tokenizer.eos_token_id

print(f"✓ Tokenizer loaded")
print(f"  - Vocab size: {len(tokenizer)}")
print(f"  - Pad token: {tokenizer.pad_token}")

# --- SPEEDUP FIX #3: Optimized LoRA Configuration ---
print("\n--- Setting up LoRA Configuration ---")
peft_config = LoraConfig(
    r=16,                                    # Rank - balance between quality and speed
    lora_alpha=32,                           # Scaling factor (typically 2*r)
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ],  # Target all attention and FFN modules
)
print("✓ LoRA config created")
print(f"  - Rank (r): {peft_config.r}")
print(f"  - Alpha: {peft_config.lora_alpha}")
print(f"  - Target modules: {len(peft_config.target_modules)}")

# --- SPEEDUP FIX #4: Optimized Training Configuration ---
print("\n" + "=" * 80)
print("--- Setting up Training Configuration ---")

training_args = SFTConfig(
    output_dir=output_dir,
    
    # --- Batch Size Optimization (using your 32GB VRAM) ---
    per_device_train_batch_size=4,          # Increased from typical 1-2
    gradient_accumulation_steps=4,           # Effective batch size = 4*4 = 16

    # --- Training Duration ---
    num_train_epochs=1,                      # Start with 1 epoch
    max_steps=-1,                            # Let epochs control training
    
    # --- Optimizer Settings ---
    optim="paged_adamw_8bit",               # Memory-efficient optimizer
    learning_rate=2e-4,
    lr_scheduler_type="cosine",              # Better convergence than constant
    warmup_ratio=0.03,
    max_grad_norm=0.3,                       # Gradient clipping
    
    # --- Performance Optimizations ---
    bf16=True,                               # Use bfloat16 precision
    tf32=True,                               # Enable TF32 for RTX 5090
    gradient_checkpointing=True,             # Saves memory
    gradient_checkpointing_kwargs={"use_reentrant": False},
    
    # --- Logging and Saving ---
    logging_steps=10,
    logging_first_step=True,
    save_strategy="steps",
    save_steps=500,
    save_total_limit=2,                      # Keep only 2 checkpoints
    
    # --- Data Loading Optimization ---
    dataloader_num_workers=4,                # Parallel data loading
    dataloader_pin_memory=True,
    group_by_length=False,                   # Disable for speed
    
    # --- Dataset Configuration ---
    max_length=2048,                     # Most vulnerability code fits here
    packing=False,                           # Set True for more speed (may affect quality)
    dataset_text_field="text",
    dataset_kwargs={"add_special_tokens": False},
    
    # --- Evaluation (Optional) ---
    # eval_strategy="steps",
    # eval_steps=500,
    # per_device_eval_batch_size=8,
    
    # --- Other Settings ---
    report_to="none",                        # Change to "wandb" or "tensorboard" if needed
    run_name=new_model_name,
)

print("✓ Training config created")
print(f"\n📊 Training Parameters:")
print(f"  - Batch size per device: {training_args.per_device_train_batch_size}")
print(f"  - Gradient accumulation steps: {training_args.gradient_accumulation_steps}")
print(f"  - Effective batch size: {training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps}")
print(f"  - Learning rate: {training_args.learning_rate}")
print(f"  - Number of epochs: {training_args.num_train_epochs}")
print(f"  - Max sequence length: {training_args.max_length}")
print(f"  - Total training samples: {len(dataset)}")
print(f"  - Estimated steps per epoch: {len(dataset) // (training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps)}")

# --- 5. Custom Callback for Monitoring ---
class SpeedMonitorCallback(TrainerCallback):
    """Callback to monitor training speed and progress"""
    
    def __init__(self):
        self.start_time = None
    
    def on_train_begin(self, args, state, control, **kwargs):
        import time
        self.start_time = time.time()
        print("\n" + "=" * 80)
        print("🚀 TRAINING STARTED")
        print("=" * 80)
    
    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs:
            import time
            elapsed = time.time() - self.start_time
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            
            log_msg = f"Step {state.global_step}"
            if "loss" in logs:
                log_msg += f" | Loss: {logs['loss']:.4f}"
            if "learning_rate" in logs:
                log_msg += f" | LR: {logs['learning_rate']:.2e}"
            if "train_samples_per_second" in logs:
                log_msg += f" | Speed: {logs['train_samples_per_second']:.2f} samples/s"
            
            log_msg += f" | Elapsed: {hours}h {minutes}m"
            print(log_msg)
    
    def on_train_end(self, args, state, control, **kwargs):
        import time
        elapsed = time.time() - self.start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        
        print("\n" + "=" * 80)
        print(f"✅ TRAINING COMPLETED")
        print(f"⏱️  Total time: {hours}h {minutes}m {seconds}s")
        print("=" * 80)

# --- 6. Initialize Trainer ---
print("\n" + "=" * 80)
print("--- Initializing SFT Trainer ---")

trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    # eval_dataset=eval_dataset,  # Add if you have eval data
    peft_config=peft_config,
    processing_class=tokenizer,
    callbacks=[SpeedMonitorCallback()],
)

print("✓ Trainer initialized")
print(f"  - Trainable parameters: {trainer.model.num_parameters():,}")

# --- 7. Start Training ---
print("\n" + "=" * 80)
print("--- Starting Training ---")
print("=" * 80)

try:
    trainer.train()
    
    print("\n" + "=" * 80)
    print("--- Saving Final Model ---")
    
    # Save the final model
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    print(f"✅ Model saved to: {output_dir}")
    print("=" * 80)
    
except KeyboardInterrupt:
    print("\n⚠️  Training interrupted by user")
    print("Saving checkpoint...")
    trainer.save_model(f"{output_dir}/interrupted_checkpoint")
    print(f"✅ Checkpoint saved to: {output_dir}/interrupted_checkpoint")

except Exception as e:
    print(f"\n❌ Training failed with error: {str(e)}")
    import traceback
    traceback.print_exc()

print("\n🎉 Script completed!")
