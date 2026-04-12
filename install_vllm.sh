#!/bin/bash
set -e

# ── Config ────────────────────────────────────────────────────────────────────
VENV=/opt/vllm-venv                  # root disk (fast, 200G)
CACHE=/workspace/.cache              # NFS fine for caches
MODEL=${1:-"votal-ai/vai35-4B"}
PORT=${2:-8000}

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

# ── Disk check ────────────────────────────────────────────────────────────────
info "Disk space:"
df -h / /workspace 2>/dev/null

# ── Caches → /workspace ───────────────────────────────────────────────────────
info "Setting caches to /workspace..."
mkdir -p $CACHE/{pip,huggingface,vllm,inductor,flashinfer,triton}

export PIP_CACHE_DIR=$CACHE/pip
export HF_HOME=$CACHE/huggingface
export HUGGINGFACE_HUB_CACHE=$CACHE/huggingface/hub
export VLLM_CACHE_ROOT=$CACHE/vllm
export TORCHINDUCTOR_CACHE_DIR=$CACHE/inductor
export FLASHINFER_CACHE_DIR=$CACHE/flashinfer
export TRITON_CACHE_DIR=$CACHE/triton

grep -q "VLLM_CACHE_ROOT" ~/.bashrc || cat >> ~/.bashrc << EOF
export PIP_CACHE_DIR=$CACHE/pip
export HF_HOME=$CACHE/huggingface
export HUGGINGFACE_HUB_CACHE=$CACHE/huggingface/hub
export VLLM_CACHE_ROOT=$CACHE/vllm
export TORCHINDUCTOR_CACHE_DIR=$CACHE/inductor
export FLASHINFER_CACHE_DIR=$CACHE/flashinfer
export TRITON_CACHE_DIR=$CACHE/triton
source $VENV/bin/activate 2>/dev/null
EOF

# ── Venv on root disk ─────────────────────────────────────────────────────────
if [ ! -f "$VENV/bin/python3" ]; then
  info "Creating venv at $VENV (root disk)..."
  rm -rf $VENV

  # Try normal venv first
  python3 -m venv $VENV 2>/dev/null || {
    warn "ensurepip missing, using --without-pip fallback..."
    python3 -m venv $VENV --without-pip
    # Bootstrap pip via get-pip.py
    curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    $VENV/bin/python3 /tmp/get-pip.py --cache-dir $CACHE/pip
    rm /tmp/get-pip.py
  }
else
  info "Venv already exists at $VENV"
fi

# ── Install vllm ──────────────────────────────────────────────────────────────
if ! $VENV/bin/python3 -c "import vllm" 2>/dev/null; then
  info "Installing vllm (this takes ~5 min)..."
  $VENV/bin/pip install vllm --cache-dir $CACHE/pip
else
  info "vllm already installed: $($VENV/bin/python3 -c 'import vllm; print(vllm.__version__)')"
fi

# Pre-compile .pyc for fast startup (avoids NFS read slowness)
info "Pre-compiling .pyc files..."
$VENV/bin/python3 -m compileall $VENV/lib/python3.12/site-packages/ -q 2>/dev/null || true

# ── ninja + nvcc ──────────────────────────────────────────────────────────────
info "Installing ninja..."
apt-get update -qq && apt-get install -y ninja-build 2>/dev/null || warn "ninja install failed"

info "Locating nvcc..."
NVCC_PATH=$(find /usr/local/cuda* -name "nvcc" 2>/dev/null | head -1)
if [ -z "$NVCC_PATH" ]; then
  warn "nvcc not found, attempting install..."
  apt-get install -y cuda-nvcc-12-8 2>/dev/null || \
  apt-get install -y cuda-toolkit-12-8 2>/dev/null || \
  warn "nvcc install failed - FlashInfer JIT will fail on first request"
  NVCC_PATH=$(find /usr/local/cuda* -name "nvcc" 2>/dev/null | head -1)
fi

if [ -n "$NVCC_PATH" ]; then
  info "nvcc: $NVCC_PATH"
  mkdir -p /usr/local/cuda/bin
  ln -sf $NVCC_PATH /usr/local/cuda/bin/nvcc 2>/dev/null || true
  export PATH=$(dirname $NVCC_PATH):$PATH
  grep -q "$(dirname $NVCC_PATH)" ~/.bashrc || \
    echo "export PATH=$(dirname $NVCC_PATH):\$PATH" >> ~/.bashrc
  nvcc --version | head -1
  ninja --version
else
  warn "nvcc not found - FlashInfer JIT will fail"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
info "Verifying..."
time $VENV/bin/python3 -c "
import vllm, torch
print(f'  vllm:  {vllm.__version__}')
print(f'  torch: {torch.__version__}')
print(f'  cuda:  {torch.cuda.is_available()}')
print(f'  gpu:   {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"none\"}')
"

# ── Serve ─────────────────────────────────────────────────────────────────────
info "Serving $MODEL on port $PORT..."
echo ""

FLASHINFER_CACHE_DIR=$CACHE/flashinfer \
VLLM_CACHE_ROOT=$CACHE/vllm \
TORCHINDUCTOR_CACHE_DIR=$CACHE/inductor \
$VENV/bin/vllm serve $MODEL \
  --host 0.0.0.0 \
  --port $PORT \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 24 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching \
  --language-model-only \
  --max-logprobs 0